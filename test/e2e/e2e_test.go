//go:build e2etests

// Package e2e contains end-to-end tests for the complete LADL service.
// Run with: go test -tags e2etests ./test/e2e/...
//
// These tests start a real HTTP server and exercise the full API surface over
// the network, validating the service behaves correctly in a realistic setting.
package e2e

import (
"bytes"
"encoding/json"
"fmt"
"io"
"net/http"
"net/http/httptest"
"strings"
"testing"

"github.com/AndrewDonelson/ladl/internal/api"
"github.com/AndrewDonelson/ladl/internal/format"
"github.com/AndrewDonelson/ladl/internal/identity"
"github.com/AndrewDonelson/ladl/internal/ledger"
)

// startServer starts a complete LADL combined server and returns its URL and
// a cleanup function.
func startServer(t *testing.T, isLedger bool) (baseURL string, cleanup func()) {
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
localSvc := &api.LocalService{
IdentityDir: dir,
Ledger:      led,
OCRPath:     "/usr/bin/tesseract",
}
ledSvc := &api.LedgerService{
Ledger:     led,
KnownPeers: func() []api.PeerInfo { return nil },
}

mux := api.NewCombinedMux(localSvc, ledSvc, isLedger)
srv := httptest.NewServer(mux)

cleanup = func() {
srv.Close()
led.Shutdown()
}
return srv.URL, cleanup
}

// localPost sends a POST from 127.0.0.1 to the given URL.
func localPost(t *testing.T, client *http.Client, url, body string) *http.Response {
t.Helper()
req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
if err != nil {
t.Fatal(err)
}
req.Header.Set("Content-Type", "application/json")
resp, err := client.Do(req)
if err != nil {
t.Fatal(err)
}
return resp
}

// localGet sends a GET to the given URL.
func localGet(t *testing.T, client *http.Client, url string) *http.Response {
t.Helper()
resp, err := client.Get(url)
if err != nil {
t.Fatal(err)
}
return resp
}

// readBody reads and closes the response body.
func readBody(t *testing.T, r *http.Response) string {
t.Helper()
defer r.Body.Close()
b, err := io.ReadAll(r.Body)
if err != nil {
t.Fatalf("read body: %v", err)
}
return string(b)
}

// TestE2E_Status_OK tests the /status endpoint via a live server.
func TestE2E_Status_OK(t *testing.T) {
baseURL, cleanup := startServer(t, false)
defer cleanup()

resp := localGet(t, http.DefaultClient, baseURL+"/status")
if resp.StatusCode != http.StatusOK {
t.Fatalf("GET /status: %d, want 200", resp.StatusCode)
}
body := readBody(t, resp)
var sr api.StatusResponse
if err := json.Unmarshal([]byte(body), &sr); err != nil {
t.Fatalf("decode status response: %v", err)
}
if sr.UUID == "" {
t.Error("UUID should not be empty")
}
}

// TestE2E_UUID_OK tests the /uuid endpoint.
func TestE2E_UUID_OK(t *testing.T) {
baseURL, cleanup := startServer(t, false)
defer cleanup()

resp := localGet(t, http.DefaultClient, baseURL+"/uuid")
if resp.StatusCode != http.StatusOK {
t.Fatalf("GET /uuid: %d, want 200", resp.StatusCode)
}
body := strings.TrimSpace(readBody(t, resp))
if len(body) != 36 {
t.Errorf("UUID length = %d, want 36: %q", len(body), body)
}
}

// TestE2E_Verify_Level1 tests POST /verify with level 1.
func TestE2E_Verify_Level1(t *testing.T) {
baseURL, cleanup := startServer(t, false)
defer cleanup()

for _, group := range []string{"a", "b", "c", "d"} {
body := fmt.Sprintf(`{"level":1,"group":"%s"}`, group)
resp := localPost(t, http.DefaultClient, baseURL+"/verify", body)
if resp.StatusCode != http.StatusOK {
t.Errorf("group %s: status %d, want 200; body=%q",
group, resp.StatusCode, readBody(t, resp))
continue
}
got := strings.TrimSpace(readBody(t, resp))
p, err := format.ParseTwoBytes(format.TwoByteResponse(got))
if err != nil {
t.Errorf("group %s: ParseTwoBytes(%q): %v", group, got, err)
continue
}
if p.G != group || p.L != 1 {
t.Errorf("group %s: two-byte = %+v, want {G:%s, L:1}", group, p, group)
}
}
}

// TestE2E_Verify_InvalidGroup tests that invalid groups return 400.
func TestE2E_Verify_InvalidGroup(t *testing.T) {
baseURL, cleanup := startServer(t, false)
defer cleanup()

for _, group := range []string{"x", "e", "Z", ""} {
body := fmt.Sprintf(`{"level":1,"group":"%s"}`, group)
resp := localPost(t, http.DefaultClient, baseURL+"/verify", body)
if resp.StatusCode != http.StatusBadRequest {
readBody(t, resp)
t.Errorf("group %q: status %d, want 400", group, resp.StatusCode)
} else {
readBody(t, resp)
}
}
}

// TestE2E_Revoke_Flow tests verify → revoke on the live server.
func TestE2E_Revoke_Flow(t *testing.T) {
baseURL, cleanup := startServer(t, false)
defer cleanup()

// Step 1: Verify.
verResp := localPost(t, http.DefaultClient, baseURL+"/verify", `{"level":1,"group":"d"}`)
if verResp.StatusCode != http.StatusOK {
t.Fatalf("verify: %d; body=%q", verResp.StatusCode, readBody(t, verResp))
}
readBody(t, verResp)

// Step 2: Revoke.
revResp := localPost(t, http.DefaultClient, baseURL+"/revoke", `{"confirm":true}`)
if revResp.StatusCode != http.StatusOK {
t.Fatalf("revoke: %d; body=%q", revResp.StatusCode, readBody(t, revResp))
}
var rr api.RevokeResponse
if err := json.Unmarshal([]byte(readBody(t, revResp)), &rr); err != nil {
t.Fatalf("decode revoke response: %v", err)
}
if !rr.Revoked {
t.Error("RevokeResponse.Revoked should be true")
}
}

// TestE2E_LedgerMode_Query tests that /q/{uuid} works in ledger mode.
func TestE2E_LedgerMode_Query(t *testing.T) {
baseURL, cleanup := startServer(t, true /* ledger mode */)
defer cleanup()

// First verify to publish a record to the ledger.
verResp := localPost(t, http.DefaultClient, baseURL+"/verify", `{"level":1,"group":"c"}`)
if verResp.StatusCode != http.StatusOK {
t.Fatalf("verify: %d; body=%q", verResp.StatusCode, readBody(t, verResp))
}
readBody(t, verResp)

// Get the UUID.
uuidResp := localGet(t, http.DefaultClient, baseURL+"/uuid")
uuid := strings.TrimSpace(readBody(t, uuidResp))
if uuidResp.StatusCode != http.StatusOK {
t.Fatalf("GET /uuid: %d", uuidResp.StatusCode)
}

// Query via ledger endpoint.
qResp := localGet(t, http.DefaultClient, baseURL+"/q/"+uuid)
if qResp.StatusCode != http.StatusOK && qResp.StatusCode != http.StatusNotFound {
t.Fatalf("GET /q/%s: %d (body=%q)", uuid, qResp.StatusCode, readBody(t, qResp))
}
readBody(t, qResp)
}

// TestE2E_PeerMode_LedgerEndpoints501 tests that ledger endpoints return 501
// in peer mode.
func TestE2E_PeerMode_LedgerEndpoints501(t *testing.T) {
baseURL, cleanup := startServer(t, false /* peer mode */)
defer cleanup()

for _, path := range []string{"/q/some-uuid", "/peers", "/sync"} {
resp := localGet(t, http.DefaultClient, baseURL+path)
if resp.StatusCode != http.StatusNotImplemented {
t.Errorf("path %s: status %d, want 501", path, resp.StatusCode)
}
readBody(t, resp)
}
}
