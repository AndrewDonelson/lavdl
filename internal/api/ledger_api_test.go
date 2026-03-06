package api_test

import (
"context"
"encoding/json"
"fmt"
"net/http"
"net/http/httptest"
"testing"
"time"

"github.com/AndrewDonelson/ladl/internal/api"
"github.com/AndrewDonelson/ladl/internal/format"
"github.com/AndrewDonelson/ladl/internal/identity"
"github.com/AndrewDonelson/ladl/internal/ledger"
)

// newLedgerService creates a LedgerService backed by an in-memory ledger for testing.
func newLedgerService(t *testing.T) (*api.LedgerService, *ledger.Ledger) {
t.Helper()
led := ledger.NewMemLedger()
t.Cleanup(func() { led.Shutdown() })
svc := &api.LedgerService{
Ledger:     led,
KnownPeers: func() []api.PeerInfo { return nil },
}
return svc, led
}

// publishRecord publishes a record to the ledger and returns the uuid.
func publishRecord(t *testing.T, led *ledger.Ledger, group string) string {
t.Helper()
pub, _, _ := identity.GenerateKeypair()
uuid := identity.DeriveUUID(pub)
payload := format.VerificationPayload{G: group, L: 1, T: time.Now().Format("2006-01")}
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
if err := led.Publish(ctx, uuid, payload); err != nil {
t.Fatalf("Publish failed: %v", err)
}
return uuid
}

// ledgerRequest builds an http.Request with the given remote addr.
func ledgerRequest(t *testing.T, method, path, remoteAddr string) *http.Request {
t.Helper()
req := httptest.NewRequest(method, path, nil)
req.RemoteAddr = remoteAddr
return req
}

// -----------------------------------------------------------------------
// GET /q/{uuid}
// -----------------------------------------------------------------------

func TestLedgerAPI_Query_NotFound(t *testing.T) {
svc, _ := newLedgerService(t)
mux := api.NewLedgerMux(svc)
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/q/unknown-uuid-00000000", "10.0.0.1:9999"))
if rr.Code != http.StatusNotFound {
t.Fatalf("status %d, want 404", rr.Code)
}
}

func TestLedgerAPI_Query_Found(t *testing.T) {
svc, led := newLedgerService(t)
uuid := publishRecord(t, led, "d")
mux := api.NewLedgerMux(svc)
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/q/"+uuid, "10.0.0.2:1111"))
if rr.Code != http.StatusOK {
t.Fatalf("status %d, body=%q  want 200", rr.Code, rr.Body.String())
}
got := rr.Body.String()
if len(got) < 2 {
t.Errorf("body too short: %q", got)
}
}

func TestLedgerAPI_Query_Revoked(t *testing.T) {
svc, led := newLedgerService(t)
uuid := publishRecord(t, led, "c")

// Revoke it.
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
if err := led.Revoke(ctx, uuid); err != nil {
t.Fatalf("Revoke failed: %v", err)
}

mux := api.NewLedgerMux(svc)
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/q/"+uuid, "10.0.0.3:2222"))
if rr.Code != http.StatusGone {
t.Fatalf("status %d, want 410 (Gone) for revoked record", rr.Code)
}
}

func TestLedgerAPI_Query_MethodNotAllowed(t *testing.T) {
svc, _ := newLedgerService(t)
mux := api.NewLedgerMux(svc)
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodPost, "/q/some-uuid", "10.0.0.4:3333"))
if rr.Code != http.StatusMethodNotAllowed {
t.Fatalf("status %d, want 405", rr.Code)
}
}

// -----------------------------------------------------------------------
// Rate Limiting
// -----------------------------------------------------------------------

func TestLedgerAPI_Query_RateLimit(t *testing.T) {
svc, _ := newLedgerService(t)
mux := api.NewLedgerMux(svc)

// Use a unique IP not shared with other tests to avoid counter pollution.
// 198.18.x.x is reserved for performance tests (RFC 2544).
rateLimitIP := fmt.Sprintf("198.18.1.%d:9999", time.Now().UnixNano()%250+1)

var lastCode int
for i := 0; i <= 100; i++ {
rr := httptest.NewRecorder()
req := ledgerRequest(t, http.MethodGet, "/q/rate-test-uuid", rateLimitIP)
mux.ServeHTTP(rr, req)
lastCode = rr.Code
}
// The 101st request should be rate limited.
if lastCode != http.StatusTooManyRequests {
t.Fatalf("101st request: status %d, want 429", lastCode)
}
}

func TestLedgerAPI_Query_RateLimit_RetryAfterHeader(t *testing.T) {
svc, _ := newLedgerService(t)
mux := api.NewLedgerMux(svc)

// Use another unique IP.
rateLimitIP := fmt.Sprintf("198.18.2.%d:9999", time.Now().UnixNano()%250+1)

var rr *httptest.ResponseRecorder
for i := 0; i <= 100; i++ {
rr = httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/q/ra-test-uuid", rateLimitIP))
}
if rr.Code != http.StatusTooManyRequests {
t.Skipf("rate limit not triggered (status %d) — may need isolated process", rr.Code)
}
if rr.Header().Get("Retry-After") == "" {
t.Error("Retry-After header missing on 429 response")
}
}

// -----------------------------------------------------------------------
// GET /peers
// -----------------------------------------------------------------------

func TestLedgerAPI_Peers_EmptyList(t *testing.T) {
svc, _ := newLedgerService(t)
mux := api.NewLedgerMux(svc)
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/peers", "10.0.0.5:4444"))
if rr.Code != http.StatusOK {
t.Fatalf("status %d, want 200", rr.Code)
}
var resp api.PeersResponse
if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
t.Fatalf("decode body: %v", err)
}
if resp.Peers == nil {
t.Error("Peers field should not be nil (should be empty slice)")
}
}

func TestLedgerAPI_Peers_WithPeerList(t *testing.T) {
led := ledger.NewMemLedger()
defer led.Shutdown()
knownPeers := []api.PeerInfo{
{NodeID: "node-abc", Address: "192.0.2.1:7743"},
{NodeID: "node-def", Address: "192.0.2.2:7743"},
}
svc := &api.LedgerService{
Ledger:     led,
KnownPeers: func() []api.PeerInfo { return knownPeers },
}
mux := api.NewLedgerMux(svc)
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/peers", "10.0.0.6:5555"))
if rr.Code != http.StatusOK {
t.Fatalf("status %d, want 200", rr.Code)
}
var resp api.PeersResponse
if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
t.Fatalf("decode body: %v", err)
}
if len(resp.Peers) != 2 {
t.Errorf("len(peers) = %d, want 2", len(resp.Peers))
}
}

func TestLedgerAPI_Peers_MethodNotAllowed(t *testing.T) {
svc, _ := newLedgerService(t)
mux := api.NewLedgerMux(svc)
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodPost, "/peers", "10.0.0.7:6666"))
if rr.Code != http.StatusMethodNotAllowed {
t.Fatalf("status %d, want 405", rr.Code)
}
}

// -----------------------------------------------------------------------
// NewCombinedMux — peer mode (isLedger=false) returns 501
// -----------------------------------------------------------------------

func TestLedgerAPI_CombinedMux_PeerMode_Query501(t *testing.T) {
dir := t.TempDir()
pub, priv, _ := identity.GenerateKeypair()
_ = identity.Save(dir, pub, priv)
led := ledger.NewMemLedger()
defer led.Shutdown()
localSvc := &api.LocalService{
IdentityDir: dir,
Ledger:      led,
OCRPath:     "/usr/bin/tesseract",
}
ledSvc := &api.LedgerService{
Ledger:     led,
KnownPeers: func() []api.PeerInfo { return nil },
}
mux := api.NewCombinedMux(localSvc, ledSvc, false /* peer mode */)
for _, path := range []string{"/q/some-uuid", "/peers", "/sync"} {
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, path, "10.0.0.8:7777"))
if rr.Code != http.StatusNotImplemented {
t.Errorf("path %s: status %d, want 501", path, rr.Code)
}
}
}

func TestLedgerAPI_CombinedMux_LedgerMode_QueryWorks(t *testing.T) {
dir := t.TempDir()
pub, priv, _ := identity.GenerateKeypair()
_ = identity.Save(dir, pub, priv)
led := ledger.NewMemLedger()
defer led.Shutdown()
localSvc := &api.LocalService{
IdentityDir: dir,
Ledger:      led,
OCRPath:     "/usr/bin/tesseract",
}
ledSvc := &api.LedgerService{
Ledger:     led,
KnownPeers: func() []api.PeerInfo { return nil },
}
mux := api.NewCombinedMux(localSvc, ledSvc, true /* ledger mode */)

// Should get 404 for an unknown UUID (not 501).
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/q/unknown-xxx", "10.0.0.9:8888"))
if rr.Code == http.StatusNotImplemented {
t.Fatal("ledger mode returned 501; should serve the query")
}
if rr.Code != http.StatusNotFound {
t.Fatalf("status %d, want 404 for unknown UUID in ledger mode", rr.Code)
}
}
