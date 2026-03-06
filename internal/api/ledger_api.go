// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// ledger_api.go — public LADL ledger HTTP API (--ledger mode): GET /q/{uuid}, GET /peers, POST /sync

// Package api — ledger_api.go implements the public LADL ledger HTTP API.
//
// This API is only available in --ledger mode.
// It exposes GET /q/{uuid}, GET /peers, and POST /sync.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/ledger"
)

// PeerInfo is a single entry in the /peers response.
type PeerInfo struct {
	Address     string `json:"address"`
	NodeID      string `json:"node_id"`
	BlockHeight int64  `json:"block_height"`
}

// PeersResponse is the JSON body for GET /peers.
type PeersResponse struct {
	Peers []PeerInfo `json:"peers"`
}

// LedgerService is the dependency bag for the ledger API.
type LedgerService struct {
	Ledger *ledger.Ledger
	// KnownPeers is a snapshot of currently connected peer metadata.
	KnownPeers func() []PeerInfo
}

// rateLimitKey groups the per-IP counters.
type rateLimitKey struct {
	IP string
}

type ipCounter struct {
	mu          sync.Mutex
	minuteCount int
	hourCount   int
	minuteReset time.Time
	hourReset   time.Time
}

var (
	rateMu  sync.Mutex
	rateMap = make(map[string]*ipCounter)
)

const (
	ratePerMinute = 100
	ratePerHour   = 1000
)

func getCounter(ip string) *ipCounter {
	rateMu.Lock()
	defer rateMu.Unlock()
	c, ok := rateMap[ip]
	if !ok {
		now := time.Now()
		c = &ipCounter{
			minuteReset: now.Add(time.Minute),
			hourReset:   now.Add(time.Hour),
		}
		rateMap[ip] = c
	}
	return c
}

func (c *ipCounter) allow() (bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if now.After(c.minuteReset) {
		c.minuteCount = 0
		c.minuteReset = now.Add(time.Minute)
	}
	if now.After(c.hourReset) {
		c.hourCount = 0
		c.hourReset = now.Add(time.Hour)
	}

	if c.minuteCount >= ratePerMinute {
		return false, time.Until(c.minuteReset)
	}
	if c.hourCount >= ratePerHour {
		return false, time.Until(c.hourReset)
	}

	c.minuteCount++
	c.hourCount++
	return true, 0
}

// NewLedgerMux builds the http.ServeMux for the ledger API.
func NewLedgerMux(svc *LedgerService) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/q/", svc.handleQuery)
	mux.HandleFunc("/peers", svc.handlePeers)
	mux.HandleFunc("/sync", svc.handleSync)
	return mux
}

// NewCombinedMux merges local and ledger muxes for running both on the same port.
// In peer mode, /q returns 501.
func NewCombinedMux(local *LocalService, led *LedgerService, isLedger bool) *http.ServeMux {
	mux := http.NewServeMux()

	// Mount local endpoints.
	mux.HandleFunc("/status", localhostOnly(local.handleStatus))
	mux.HandleFunc("/uuid", localhostOnly(local.handleUUID))
	mux.HandleFunc("/verify", localhostOnly(local.handleVerify))
	mux.HandleFunc("/revoke", localhostOnly(local.handleRevoke))

	if isLedger {
		// Ledger public endpoints — no localhost restriction.
		mux.HandleFunc("/q/", led.handleQuery)
		mux.HandleFunc("/peers", led.handlePeers)
		mux.HandleFunc("/sync", led.handleSync)
	} else {
		// Return 501 for ledger-only endpoints in peer mode.
		notLedger := func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, ladlerrors.ErrLedgerModeRequired.Error(), http.StatusNotImplemented)
		}
		mux.HandleFunc("/q/", notLedger)
		mux.HandleFunc("/peers", notLedger)
		mux.HandleFunc("/sync", notLedger)
	}
	return mux
}

// GET /q/{uuid}
func (svc *LedgerService) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}
	counter := getCounter(host)
	ok, retryAfter := counter.allow()
	if !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		http.Error(w, ladlerrors.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	// Extract UUID from path /q/{uuid}.
	uuid := strings.TrimPrefix(r.URL.Path, "/q/")
	if uuid == "" {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp, status, err := svc.Ledger.Query(ctx, uuid)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	switch status {
	case ledger.StatusRevoked:
		w.WriteHeader(http.StatusGone)
		// empty body
		return
	case ledger.StatusUnknown:
		if err != nil && err.Error() != ladler_not_found_sentinel {
			_ = err
		}
		w.WriteHeader(http.StatusNotFound)
		return
	default:
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, resp)
	}
}

// sentinel used to detect "not found" without importing l4 here.
const ladler_not_found_sentinel = ""

// GET /peers
func (svc *LedgerService) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var peers []PeerInfo
	if svc.KnownPeers != nil {
		peers = svc.KnownPeers()
	}
	if peers == nil {
		peers = []PeerInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PeersResponse{Peers: peers})
}

// POST /sync — internal P2P endpoint.
func (svc *LedgerService) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Handled by Strata L4 transport layer directly.
	w.WriteHeader(http.StatusOK)
}
