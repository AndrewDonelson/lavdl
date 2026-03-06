package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/api"
	"github.com/AndrewDonelson/ladl/internal/format"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/ledger"
	"github.com/AndrewDonelson/ladl/internal/verification"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

// compile-time checks
var (
	_ = ladlerrors.ErrIdentityNotFound
	_ = (*verification.Record)(nil)
)

// newTestService creates a LocalService backed by an in-memory ledger and a
// temp identity directory populated with a fresh keypair.
func newTestService(t *testing.T) (*api.LocalService, string /*uuid*/) {
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
	return svc, uid.UUID
}

// localRequest creates a fake http.Request that appears to come from 127.0.0.1.
func localRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	var buf *bytes.Buffer
	if body != "" {
		buf = bytes.NewBufferString(body)
	} else {
		buf = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, buf)
	req.RemoteAddr = "127.0.0.1:12345"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// remoteRequest creates a fake http.Request from a non-local address.
func remoteRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "203.0.113.5:9999"
	return req
}

// -----------------------------------------------------------------------
// GET /status
// -----------------------------------------------------------------------

func TestLocalAPI_Status_OK(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodGet, "/status", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	var resp api.StatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.UUID == "" {
		t.Error("UUID should not be empty")
	}
}

func TestLocalAPI_Status_RemoteRejected(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, remoteRequest(t, http.MethodGet, "/status"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rr.Code)
	}
}

func TestLocalAPI_Status_MethodNotAllowed(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/status", ""))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rr.Code)
	}
}

// -----------------------------------------------------------------------
// GET /uuid
// -----------------------------------------------------------------------

func TestLocalAPI_UUID_OK(t *testing.T) {
	svc, uuid := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodGet, "/uuid", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != uuid {
		t.Errorf("body = %q, want %q", got, uuid)
	}
}

func TestLocalAPI_UUID_RemoteRejected(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, remoteRequest(t, http.MethodGet, "/uuid"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rr.Code)
	}
}

// -----------------------------------------------------------------------
// POST /verify
// -----------------------------------------------------------------------

func TestLocalAPI_Verify_Level1_OK(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"level":1,"group":"d"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, body=%q  want 200", rr.Code, rr.Body.String())
	}
	got := strings.TrimSpace(rr.Body.String())
	p, err := format.ParseTwoBytes(format.TwoByteResponse(got))
	if err != nil {
		t.Fatalf("ParseTwoBytes(%q): %v", got, err)
	}
	if p.G != "d" {
		t.Errorf("group = %q, want %q", p.G, "d")
	}
	if p.L != 1 {
		t.Errorf("level = %d, want 1", p.L)
	}
}

func TestLocalAPI_Verify_InvalidGroup(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"level":1,"group":"z"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rr.Code)
	}
}

func TestLocalAPI_Verify_UppercaseGroupRejected(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"level":1,"group":"D"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for uppercase group", rr.Code)
	}
}

func TestLocalAPI_Verify_MissingBody(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", ""))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rr.Code)
	}
}

func TestLocalAPI_Verify_Level3_NotImplemented(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"level":3,"group":"d"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501", rr.Code)
	}
}

// -----------------------------------------------------------------------
// POST /revoke
// -----------------------------------------------------------------------

func TestLocalAPI_Revoke_OK(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	// First, publish a record via verify.
	verifyBody := `{"level":1,"group":"c"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", verifyBody))
	if rr.Code != http.StatusOK {
		t.Fatalf("verify status %d, body=%q", rr.Code, rr.Body.String())
	}
	// Now revoke.
	revokeBody := `{"confirm":true}`
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, localRequest(t, http.MethodPost, "/revoke", revokeBody))
	if rr2.Code != http.StatusOK {
		t.Fatalf("revoke status %d, body=%q  want 200", rr2.Code, rr2.Body.String())
	}
	var resp api.RevokeResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode revoke body: %v", err)
	}
	if !resp.Revoked {
		t.Error("Revoked field should be true")
	}
}

func TestLocalAPI_Revoke_NeedsConfirm(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"confirm":false}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/revoke", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rr.Code)
	}
}

func TestLocalAPI_Revoke_NoRecord(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	// No verify done first — should 404.
	body := `{"confirm":true}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/revoke", body))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 (no record to revoke)", rr.Code)
	}
}

func TestLocalAPI_Revoke_RemoteRejected(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"confirm":true}`
	req := remoteRequest(t, http.MethodPost, "/revoke")
	req.Body = http.NoBody
	_ = body
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rr.Code)
	}
}

// -----------------------------------------------------------------------
// Ledger mode 501 for ledger endpoints
// -----------------------------------------------------------------------

func TestLocalAPI_PeerMode_LedgerEndpointReturns501(t *testing.T) {
	svc, _ := newTestService(t)
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ledSvc := &api.LedgerService{
		Ledger:     led,
		KnownPeers: func() []api.PeerInfo { return nil },
	}
	mux := api.NewCombinedMux(svc, ledSvc, false /* peer mode */)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodGet, "/q/some-uuid", ""))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501 in peer mode", rr.Code)
	}
}

// -----------------------------------------------------------------------
// ensure verification creates new identity if one doesn't exist yet
// -----------------------------------------------------------------------

func TestLocalAPI_Verify_AutoCreateIdentity(t *testing.T) {
	dir := t.TempDir()
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	svc := &api.LocalService{
		IdentityDir: dir,
		Ledger:      led,
		OCRPath:     "/usr/bin/tesseract",
	}
	mux := api.NewLocalMux(svc)
	body := `{"level":1,"group":"b"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d (auto create), body=%q", rr.Code, rr.Body.String())
	}
	_, _, _, err := identity.Load(dir)
	if err != nil {
		t.Errorf("identity not persisted after auto-create: %v", err)
	}
}
