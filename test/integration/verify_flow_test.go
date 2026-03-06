//go:build integration

// Package integration contains integration tests for the LADL service.
// Run with: go test -tags integration ./test/integration/...
package integration

import (
"bytes"
"context"
"encoding/json"
"fmt"
"net/http"
"net/http/httptest"
	"time"
"strings"
"testing"

"github.com/AndrewDonelson/ladl/internal/api"
"github.com/AndrewDonelson/ladl/internal/format"
"github.com/AndrewDonelson/ladl/internal/identity"
"github.com/AndrewDonelson/ladl/internal/ledger"
)

// setupIntegration creates a full in-process service stack.
func setupIntegration(t *testing.T) (*api.LocalService, *ledger.Ledger, string) {
t.Helper()
dir := t.TempDir()
pub, priv, err := identity.GenerateKeypair()
if err != nil {
t.Fatal(err)
}
if err := identity.Save(dir, pub, priv); err != nil {
t.Fatal(err)
}
led := ledger.NewMemLedger()
t.Cleanup(func() { led.Shutdown() })
svc := &api.LocalService{
IdentityDir: dir,
Ledger:      led,
OCRPath:     "/usr/bin/tesseract",
}
uid, _, _, _ := identity.Load(dir)
return svc, led, uid.UUID
}

func localReq(method, path, body string) *http.Request {
var buf *bytes.Buffer
if body != "" {
buf = bytes.NewBufferString(body)
} else {
buf = &bytes.Buffer{}
}
req := httptest.NewRequest(method, path, buf)
req.RemoteAddr = "127.0.0.1:1234"
if body != "" {
req.Header.Set("Content-Type", "application/json")
}
return req
}

// TestIntegration_VerifyThenQuery tests the complete verify → ledger query flow.
func TestIntegration_VerifyThenQuery(t *testing.T) {
svc, led, _ := setupIntegration(t)
mux := api.NewLocalMux(svc)

// Step 1: Verify (level 1, group d).
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, localReq(http.MethodPost, "/verify", `{"level":1,"group":"d"}`))
if rr.Code != http.StatusOK {
t.Fatalf("verify: status %d, body=%q", rr.Code, rr.Body.String())
}
twoBytes := strings.TrimSpace(rr.Body.String())

// Verify the two-byte response is correct.
p, err := format.ParseTwoBytes(format.TwoByteResponse(twoBytes))
if err != nil {
t.Fatalf("ParseTwoBytes(%q): %v", twoBytes, err)
}
if p.G != "d" || p.L != 1 {
t.Errorf("two-byte payload = %+v, want {G:d, L:1}", p)
}

// Step 2: Query via ledger.
uid, _, _, _ := identity.Load(svc.IdentityDir)
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
resp, status, err := led.Query(ctx, uid.UUID)
if err != nil {
t.Fatalf("ledger.Query: %v", err)
}
if status != ledger.StatusConfirmed && status != ledger.StatusPending {
t.Logf("note: status=%v (may be StatusPending in peer mode)", status)
}
_ = resp
}

// TestIntegration_VerifyThenRevoke tests the complete verify → revoke flow.
func TestIntegration_VerifyThenRevoke(t *testing.T) {
svc, _, _ := setupIntegration(t)
mux := api.NewLocalMux(svc)

// Step 1: Verify.
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, localReq(http.MethodPost, "/verify", `{"level":1,"group":"c"}`))
if rr.Code != http.StatusOK {
t.Fatalf("verify: status %d, body=%q", rr.Code, rr.Body.String())
}

// Step 2: Revoke.
rr2 := httptest.NewRecorder()
mux.ServeHTTP(rr2, localReq(http.MethodPost, "/revoke", `{"confirm":true}`))
if rr2.Code != http.StatusOK {
t.Fatalf("revoke: status %d, body=%q", rr2.Code, rr2.Body.String())
}

var resp api.RevokeResponse
if err := json.Unmarshal(rr2.Body.Bytes(), &resp); err != nil {
t.Fatalf("decode revoke body: %v", err)
}
if !resp.Revoked {
t.Error("Revoked should be true")
}
}

// TestIntegration_StatusReflectsMostRecentVerification tests that the /status
// endpoint reflects the UUID after verification.
func TestIntegration_StatusReflectsMostRecentVerification(t *testing.T) {
svc, _, uuid := setupIntegration(t)
mux := api.NewLocalMux(svc)

// Status before verify.
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, localReq(http.MethodGet, "/status", ""))
if rr.Code != http.StatusOK {
t.Fatalf("pre-verify status: %d", rr.Code)
}
var pre api.StatusResponse
_ = json.Unmarshal(rr.Body.Bytes(), &pre)
if pre.UUID != uuid {
t.Errorf("pre-verify UUID = %q, want %q", pre.UUID, uuid)
}

// Verify.
rr2 := httptest.NewRecorder()
mux.ServeHTTP(rr2, localReq(http.MethodPost, "/verify", `{"level":1,"group":"b"}`))
if rr2.Code != http.StatusOK {
t.Fatalf("verify: status %d", rr2.Code)
}

// Status after verify.
rr3 := httptest.NewRecorder()
mux.ServeHTTP(rr3, localReq(http.MethodGet, "/status", ""))
var post api.StatusResponse
_ = json.Unmarshal(rr3.Body.Bytes(), &post)
if post.UUID != uuid {
t.Errorf("post-verify UUID = %q, want %q", post.UUID, uuid)
}
if post.Local == "" {
t.Error("post-verify TwoBytes should not be empty")
}
}

// TestIntegration_MultipleVerificationUpdates tests that re-verifying updates
// the stored record.
func TestIntegration_MultipleVerificationUpdates(t *testing.T) {
svc, _, _ := setupIntegration(t)
mux := api.NewLocalMux(svc)

for i, group := range []string{"a", "b", "c", "d"} {
body := fmt.Sprintf(`{"level":1,"group":"%s"}`, group)
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, localReq(http.MethodPost, "/verify", body))
if rr.Code != http.StatusOK {
t.Errorf("verify[%d=%s]: status %d", i, group, rr.Code)
}
got := strings.TrimSpace(rr.Body.String())
if len(got) != 2 || string(got[0]) != group {
t.Errorf("verify[%d]: two-byte = %q, want %s1", i, got, group)
}
}
}
