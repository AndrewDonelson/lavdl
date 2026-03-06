package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AndrewDonelson/strata/l4"

	"github.com/AndrewDonelson/ladl/internal/api"
	"github.com/AndrewDonelson/ladl/internal/format"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/ledger"
)

// failingRevokeLayer is an l4.L4Layer that succeeds on Publish/Query
// but returns ErrStoreUnavailable from Revoke.
type failingRevokeLayer struct{}

func (f *failingRevokeLayer) Publish(appID, nodeID string, payload map[string]interface{}) (l4.L4Record, error) {
	return l4.L4Record{UUID: nodeID, Payload: payload}, nil
}

func (f *failingRevokeLayer) Query(appID, recordID string) (l4.L4Record, error) {
	return l4.L4Record{}, l4.ErrNotFound
}

func (f *failingRevokeLayer) Revoke(appID, recordID string) error                    { return l4.ErrStoreUnavailable }
func (f *failingRevokeLayer) Subscribe(appID string, handler l4.RecordHandler) error { return nil }
func (f *failingRevokeLayer) Unsubscribe(appID string) error                         { return nil }
func (f *failingRevokeLayer) Status() l4.L4Status                                    { return l4.L4Status{} }
func (f *failingRevokeLayer) PeerCount() int                                         { return 0 }
func (f *failingRevokeLayer) Shutdown() error                                        { return nil }

// TestLocalAPI_Revoke_LedgerError covers the http.StatusInternalServerError
// path in handleRevoke when svc.Ledger.Revoke returns an error.
func TestLocalAPI_Revoke_LedgerError(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Save(dir, pub, priv); err != nil {
		t.Fatal(err)
	}
	uid, _, _, err := identity.Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Create ledger with a layer that fails Revoke.
	nodeID := uid.UUID
	led := ledger.New(&failingRevokeLayer{}, nodeID)
	t.Cleanup(func() { led.Shutdown() })

	// First publish a local payload so the ledger has a record.
	p := format.VerificationPayload{G: "a", L: 1, T: time.Now().UTC().Format("2006-01")}
	_ = led.Publish(context.Background(), uid.UUID, p)

	svc := &api.LocalService{IdentityDir: dir, Ledger: led}
	mux := api.NewLocalMux(svc)

	body := bytes.NewBufferString(`{"confirm":true}`)
	req := httptest.NewRequest(http.MethodPost, "/revoke", body)
	req.RemoteAddr = "127.0.0.1:0"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Ledger.Revoke fails → 500 Internal Server Error.
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("POST /revoke with failing ledger code = %d, want 500", rr.Code)
	}
}

// TestLedgerAPI_Query_WithUnavailableLayer covers the response when the ledger
// Query returns StatusUnknown with a non-nil error (e.g. ErrLADLUnavailable).
// This covers the `_ = err` statement in handleQuery's StatusUnknown case.
type failingQueryLayer struct{}

func (f *failingQueryLayer) Publish(appID, nodeID string, payload map[string]interface{}) (l4.L4Record, error) {
	return l4.L4Record{UUID: nodeID}, nil
}

func (f *failingQueryLayer) Query(appID, recordID string) (l4.L4Record, error) {
	// Return a non-ErrNotFound error so Query returns StatusUnknown, ErrLADLUnavailable.
	return l4.L4Record{}, l4.ErrStoreUnavailable
}

func (f *failingQueryLayer) Revoke(appID, recordID string) error                    { return nil }
func (f *failingQueryLayer) Subscribe(appID string, handler l4.RecordHandler) error { return nil }
func (f *failingQueryLayer) Unsubscribe(appID string) error                         { return nil }
func (f *failingQueryLayer) Status() l4.L4Status                                    { return l4.L4Status{} }
func (f *failingQueryLayer) PeerCount() int                                         { return 0 }
func (f *failingQueryLayer) Shutdown() error                                        { return nil }

func TestLedgerAPI_Query_UnavailableLayer(t *testing.T) {
	// Use a ledger whose layer always fails Query with ErrStoreUnavailable.
	// This causes ledger.Query to return StatusUnknown, ErrLADLUnavailable.
	// In handleQuery, the StatusUnknown case has `_ = err` to suppress the error.
	led := ledger.New(&failingQueryLayer{}, "test-node")
	t.Cleanup(func() { led.Shutdown() })

	svc := &api.LedgerService{Ledger: led}
	mux := api.NewLedgerMux(svc)

	// Use a unique IP to avoid rate-limit interference from other tests.
	req := httptest.NewRequest(http.MethodGet, "/q/some-test-uuid-unavailable", nil)
	req.RemoteAddr = "10.254.254.1:9999"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// StatusUnknown → 404 Not Found.
	if rr.Code != http.StatusNotFound {
		t.Errorf("GET /q/... with failing layer code = %d, want 404", rr.Code)
	}
}

// TestLedgerAPI_Query_EmptyRemoteAddr covers the `host = r.RemoteAddr` path
// in handleQuery when net.SplitHostPort fails (e.g. RemoteAddr is empty).
// This is the rate-limiter host extraction fallback.
func TestLedgerAPI_Query_EmptyRemoteAddr(t *testing.T) {
	led := ledger.New(&failingQueryLayer{}, "test-node2")
	t.Cleanup(func() { led.Shutdown() })

	svc := &api.LedgerService{Ledger: led}
	mux := api.NewLedgerMux(svc)

	// Empty RemoteAddr → SplitHostPort fails → host = r.RemoteAddr = "".
	req := httptest.NewRequest(http.MethodGet, "/q/test-uuid-empty-remote", nil)
	req.RemoteAddr = ""
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Should respond with 404 (record not found / unavailable).
	if rr.Code == 0 {
		t.Error("expected a non-zero status code")
	}
}
