// Package ledger wraps Strata L4 to provide LADL-specific publish/query/revoke APIs.
package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/AndrewDonelson/strata/l4"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/format"
)

const (
	// AppID is the L4 application namespace for all LADL records.
	AppID = "ladl"
)

// RecordStatus describes the lifecycle state of a LADL record on the ledger.
type RecordStatus int

const (
	StatusUnknown   RecordStatus = iota // UUID not found
	StatusPending                       // published, quorum not yet met
	StatusConfirmed                     // quorum met
	StatusRevoked                       // revoked via Revoke()
)

// localEntry is an in-process fallback/local record store used when the L4 layer
// is unavailable. It is also used by tests.
type localEntry struct {
	Payload format.VerificationPayload
	Status  RecordStatus
	At      time.Time
}

// Ledger manages L4 read/write for the LADL app.
type Ledger struct {
	layer  l4.L4Layer
	nodeID string
	// localmu guards localRecords for thread-safe access.
	localmu      sync.RWMutex
	localRecords map[string]*localEntry // uuid -> entry
}

// New creates a Ledger backed by the provided L4Layer.
func New(layer l4.L4Layer, nodeID string) *Ledger {
	return &Ledger{
		layer:        layer,
		nodeID:       nodeID,
		localRecords: make(map[string]*localEntry),
	}
}

// NewMemLedger creates an in-memory-only ledger suitable for tests.
func NewMemLedger() *Ledger {
	store := l4.NewMemStore()
	signer, _ := l4.NewSigner()
	hub := l4.NewMemTransportHub()
	nodeID := signer.PublicKeyHex()
	transport := l4.NewMemTransport(nodeID, 10, hub, nil)
	cfg := l4.Config{
		Enabled:  true,
		Mode:     "peer",
		Quorum:   1,
		MaxPeers: 10,
	}
	layer, err := l4.NewWithComponents(cfg, signer, store, transport)
	if err != nil {
		panic("NewMemLedger: " + err.Error())
	}
	return New(layer, nodeID)
}

// Publish records a verification payload to the LADL for the given UUID.
// If the L4 layer is unavailable, the record is saved locally and ErrLADLUnavailable
// is returned (it will sync when connectivity resumes).
func (led *Ledger) Publish(ctx context.Context, uuid string, p format.VerificationPayload) error {
	led.saveLocally(uuid, p)

	payload, err := payloadToMap(p)
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	_, err = led.layer.Publish(AppID, uuid, payload)
	if errors.Is(err, l4.ErrAlreadyPublished) {
		// Update instead by revoking and re-publishing.
		_ = led.layer.Revoke(AppID, uuid)
		_, err = led.layer.Publish(AppID, uuid, payload)
		if err != nil {
			return ladlerrors.ErrLADLUnavailable
		}
		led.saveLocally(uuid, p)
		return nil
	}
	if err != nil {
		return ladlerrors.ErrLADLUnavailable
	}
	return nil
}

// Query returns the two-byte verification response for a UUID.
// Returns ("", StatusUnknown, nil) if the UUID is not found.
// Returns ("", StatusRevoked, ErrLADLRecordRevoked) if the UUID is revoked.
func (led *Ledger) Query(ctx context.Context, uuid string) (format.TwoByteResponse, RecordStatus, error) {
	if led.layer == nil {
		return "", StatusUnknown, ladlerrors.ErrLADLUnavailable
	}

	// Try L4 layer first.
	rec, err := led.layer.Query(AppID, uuid)
	if err == nil {
		if rec.Revoked {
			return "", StatusRevoked, ladlerrors.ErrLADLRecordRevoked
		}
		p, parseErr := mapToPayload(rec.Payload)
		if parseErr != nil {
			return "", StatusUnknown, parseErr
		}
		return format.FormatTwoBytes(p), StatusConfirmed, nil
	}

	if errors.Is(err, l4.ErrNotFound) {
		// Fall through to local cache.
		led.localmu.RLock()
		entry, ok := led.localRecords[uuid]
		led.localmu.RUnlock()
		if ok {
			if entry.Status == StatusRevoked {
				return "", StatusRevoked, ladlerrors.ErrLADLRecordRevoked
			}
			return format.FormatTwoBytes(entry.Payload), entry.Status, nil
		}
		return "", StatusUnknown, nil
	}

	return "", StatusUnknown, ladlerrors.ErrLADLUnavailable
}

// Revoke marks a UUID's record as revoked on the LADL.
func (led *Ledger) Revoke(ctx context.Context, uuid string) error {
	err := led.layer.Revoke(AppID, uuid)
	if err != nil && !errors.Is(err, l4.ErrNotFound) {
		return ladlerrors.ErrLADLUnavailable
	}

	led.localmu.Lock()
	if entry, ok := led.localRecords[uuid]; ok {
		entry.Status = StatusRevoked
	} else {
		led.localRecords[uuid] = &localEntry{Status: StatusRevoked, At: time.Now()}
	}
	led.localmu.Unlock()
	return nil
}

// LocalPayload returns the locally-cached payload for a UUID (used for /status).
func (led *Ledger) LocalPayload(uuid string) (format.VerificationPayload, bool) {
	led.localmu.RLock()
	entry, ok := led.localRecords[uuid]
	led.localmu.RUnlock()
	if !ok {
		return format.VerificationPayload{}, false
	}
	return entry.Payload, true
}

// PeerCount returns the number of connected peers.
func (led *Ledger) PeerCount() int {
	if led.layer == nil {
		return 0
	}
	return led.layer.PeerCount()
}

// Shutdown shuts down the L4 layer.
func (led *Ledger) Shutdown() error {
	if led.layer == nil {
		return nil
	}
	return led.layer.Shutdown()
}

// saveLocally stores a record in the in-process local cache.
func (led *Ledger) saveLocally(uuid string, p format.VerificationPayload) {
	led.localmu.Lock()
	led.localRecords[uuid] = &localEntry{
		Payload: p,
		Status:  StatusPending,
		At:      time.Now(),
	}
	led.localmu.Unlock()
}

// payloadToMap serialises a VerificationPayload into a map for L4.
func payloadToMap(p format.VerificationPayload) (map[string]interface{}, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// mapToPayload deserialises a map from L4 into a VerificationPayload.
func mapToPayload(m map[string]interface{}) (format.VerificationPayload, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return format.VerificationPayload{}, err
	}
	var p format.VerificationPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return format.VerificationPayload{}, err
	}
	return p, nil
}
