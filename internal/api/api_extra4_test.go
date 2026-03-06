package api_test

import (
"bytes"
"net/http"
"net/http/httptest"
"os"
"testing"

"github.com/AndrewDonelson/ladl/internal/api"
"github.com/AndrewDonelson/ladl/internal/ledger"
)

// TestLocalAPI_Verify_SaveIdentityFails covers the `saveErr != nil` path
// inside handleVerify: when identity.Load fails (no existing identity) and
// then identity.Save also fails because the IdentityDir is read-only.
// This exercises the 500 "failed to save identity" response.
func TestLocalAPI_Verify_SaveIdentityFails(t *testing.T) {
if os.Getuid() == 0 {
t.Skip("root bypasses permission checks")
}

// readonly dir: Load will return ErrIdentityNotFound, Save will fail EACCES.
dir := t.TempDir()
if err := os.Chmod(dir, 0500); err != nil {
t.Fatalf("chmod failed: %v", err)
}
t.Cleanup(func() { os.Chmod(dir, 0700) })

led := ledger.New(&failingRevokeLayer{}, "test-save-fails")
t.Cleanup(func() { led.Shutdown() })

svc := &api.LocalService{IdentityDir: dir, Ledger: led}
mux := api.NewLocalMux(svc)

body := bytes.NewBufferString(`{"level":1,"group":"c"}`)
req := httptest.NewRequest(http.MethodPost, "/verify", body)
req.RemoteAddr = "127.0.0.1:0"
req.Header.Set("Content-Type", "application/json")
rr := httptest.NewRecorder()
mux.ServeHTTP(rr, req)

if rr.Code != http.StatusInternalServerError {
t.Errorf("POST /verify with read-only identityDir: code = %d, want 500", rr.Code)
}
}
