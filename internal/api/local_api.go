// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// local_api.go — local peer-mode HTTP API restricted to 127.0.0.1: /uuid, /status, /verify, /revoke

// Package api implements the LADL local (peer mode) HTTP API.
//
// All endpoints are restricted to 127.0.0.1 or the Unix domain socket.
// Requests from any other origin return 403.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/format"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/ledger"
	"github.com/AndrewDonelson/ladl/internal/verification"
)

// LocalService is the dependency bag for the local API.
type LocalService struct {
	IdentityDir string
	Ledger      *ledger.Ledger
	OCRPath     string // path to tesseract binary
}

// StatusResponse is the JSON body for GET /status.
type StatusResponse struct {
	UUID            string `json:"uuid"`
	Local           string `json:"local"`
	Public          string `json:"public"`
	PublicSyncedAt  string `json:"public_synced_at,omitempty"`
	PublicReachable bool   `json:"public_reachable"`
}

// RevokeResponse is the JSON body for POST /revoke.
type RevokeResponse struct {
	UUID    string `json:"uuid"`
	Revoked bool   `json:"revoked"`
}

// NewLocalMux builds the http.ServeMux for the local API.
func NewLocalMux(svc *LocalService) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", localhostOnly(svc.handleStatus))
	mux.HandleFunc("/uuid", localhostOnly(svc.handleUUID))
	mux.HandleFunc("/verify", localhostOnly(svc.handleVerify))
	mux.HandleFunc("/revoke", localhostOnly(svc.handleRevoke))
	return mux
}

// localhostOnly wraps a handler and rejects non-localhost connections.
func localhostOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		// Unix socket connections have an empty RemoteAddr — allow those.
		// Non-empty means TCP; only accept loopback.
		if host != "127.0.0.1" && host != "::1" && host != "" {
			http.Error(w, ladlerrors.ErrRemoteRequestDenied.Error(), http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// GET /status
func (svc *LocalService) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, _, _, err := identity.Load(svc.IdentityDir)
	var localStr string
	var uuid string
	if err != nil {
		// No identity — return "-0".
		localStr = "-0"
		uuid = ""
	} else {
		uuid = uid.UUID
		if p, ok := svc.Ledger.LocalPayload(uuid); ok {
			localStr = string(format.FormatTwoBytes(p))
		} else {
			localStr = "-0"
		}
	}

	// Query public ledger.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	publicStr := localStr
	publicReachable := false
	var syncedAt string
	if uuid != "" {
		resp, _, qErr := svc.Ledger.Query(ctx, uuid)
		if qErr == nil {
			publicStr = string(resp)
			publicReachable = true
			syncedAt = time.Now().UTC().Format("2006-01")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StatusResponse{
		UUID:            uuid,
		Local:           localStr,
		Public:          publicStr,
		PublicSyncedAt:  syncedAt,
		PublicReachable: publicReachable,
	})
}

// GET /uuid
func (svc *LocalService) handleUUID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, _, _, err := identity.Load(svc.IdentityDir)
	if err != nil {
		http.Error(w, ladlerrors.ErrIdentityNotFound.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, uid.UUID)
}

// verifyRequest is the JSON body for POST /verify.
type verifyRequest struct {
	Group        string `json:"group"`
	Level        int    `json:"level"`
	DocumentPath string `json:"document_path,omitempty"`
}

// POST /verify
func (svc *LocalService) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Level == 0 && req.Group == "") {
		http.Error(w, "bad request: missing body or level", http.StatusBadRequest)
		return
	}
	if req.Level < 1 || req.Level > 3 {
		http.Error(w, "bad request: level must be 1, 2, or 3", http.StatusBadRequest)
		return
	}

	// Reject uppercase groups immediately.
	if req.Group != "" && req.Group != strings.ToLower(req.Group) {
		http.Error(w, ladlerrors.ErrInvalidAgeGroup.Error(), http.StatusBadRequest)
		return
	}

	uid, _, priv, err := identity.Load(svc.IdentityDir)
	if err != nil {
		// Generate identity on first verify.
		pub, privKey, genErr := identity.GenerateKeypair()
		if genErr != nil {
			http.Error(w, "failed to generate identity", http.StatusInternalServerError)
			return
		}
		if saveErr := identity.Save(svc.IdentityDir, pub, privKey); saveErr != nil {
			http.Error(w, "failed to save identity", http.StatusInternalServerError)
			return
		}
		uid, _, priv, err = identity.Load(svc.IdentityDir)
		if err != nil {
			http.Error(w, "failed to load new identity", http.StatusInternalServerError)
			return
		}
	}

	var rec *verification.Record
	switch req.Level {
	case 1:
		if err := format.ValidateGroup(req.Group); err != nil {
			http.Error(w, ladlerrors.ErrInvalidAgeGroup.Error(), http.StatusBadRequest)
			return
		}
		rec, err = verification.Level1(req.Group, uid.UUID, priv)
	case 2:
		if req.DocumentPath == "" {
			http.Error(w, "bad request: document_path required for level 2", http.StatusBadRequest)
			return
		}
		opts := &verification.L2Options{
			OCR: &verification.TesseractExtractor{BinaryPath: svc.OCRPath},
		}
		rec, err = verification.Level2(req.DocumentPath, uid.UUID, priv, opts)
	case 3:
		http.Error(w, "level 3 requires VC document via dedicated endpoint", http.StatusNotImplemented)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Publish to ledger.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	_ = svc.Ledger.Publish(ctx, uid.UUID, rec.Payload)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, format.FormatTwoBytes(rec.Payload))
}

// revokeRequest is the JSON body for POST /revoke.
type revokeRequest struct {
	Confirm bool `json:"confirm"`
}

// POST /revoke
func (svc *LocalService) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Confirm {
		http.Error(w, "bad request: confirm must be true", http.StatusBadRequest)
		return
	}

	uid, _, _, err := identity.Load(svc.IdentityDir)
	if err != nil {
		http.Error(w, ladlerrors.ErrIdentityNotFound.Error(), http.StatusNotFound)
		return
	}

	// Check that a record exists before revoking.
	if _, ok := svc.Ledger.LocalPayload(uid.UUID); !ok {
		http.Error(w, ladlerrors.ErrIdentityNotFound.Error(), http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := svc.Ledger.Revoke(ctx, uid.UUID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RevokeResponse{
		UUID:    uid.UUID,
		Revoked: true,
	})
}
