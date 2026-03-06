package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/api"
	"github.com/AndrewDonelson/ladl/internal/ledger"
)

// -----------------------------------------------------------------------
// GET /uuid — no identity
// -----------------------------------------------------------------------

func TestLocalAPI_UUID_NoIdentity(t *testing.T) {
	dir := t.TempDir() // empty — no identity saved
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	svc := &api.LocalService{
		IdentityDir: dir,
		Ledger:      led,
	}
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodGet, "/uuid", ""))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 (no identity)", rr.Code)
	}
}

// -----------------------------------------------------------------------
// GET /status — no identity (returns "-0" local)
// -----------------------------------------------------------------------

func TestLocalAPI_Status_NoIdentity(t *testing.T) {
	dir := t.TempDir() // empty — no identity
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	svc := &api.LocalService{
		IdentityDir: dir,
		Ledger:      led,
	}
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodGet, "/status", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 even with no identity", rr.Code)
	}
	body := rr.Body.String()
	if body == "" {
		t.Error("body should not be empty")
	}
}

// -----------------------------------------------------------------------
// POST /verify — edge cases
// -----------------------------------------------------------------------

func TestLocalAPI_Verify_Level2_MissingDocumentPath(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"level":2,"group":"d"}` // level 2 requires document_path
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (missing document_path for level 2)", rr.Code)
	}
}

func TestLocalAPI_Verify_InvalidLevel_Zero(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"level":0,"group":"d"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (level=0)", rr.Code)
	}
}

func TestLocalAPI_Verify_InvalidLevel_Four(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{"level":4,"group":"d"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (level=4)", rr.Code)
	}
}

func TestLocalAPI_Verify_MethodNotAllowed(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodGet, "/verify", ""))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rr.Code)
	}
}

func TestLocalAPI_Verify_InvalidJSON(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	body := `{not valid json}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/verify", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (invalid JSON)", rr.Code)
	}
}

// -----------------------------------------------------------------------
// POST /revoke — no identity in dir
// -----------------------------------------------------------------------

func TestLocalAPI_Revoke_NoIdentity(t *testing.T) {
	dir := t.TempDir()
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	svc := &api.LocalService{
		IdentityDir: dir, // no identity here
		Ledger:      led,
	}
	mux := api.NewLocalMux(svc)
	body := `{"confirm":true}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodPost, "/revoke", body))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 (no identity)", rr.Code)
	}
}

func TestLocalAPI_Revoke_MethodNotAllowed(t *testing.T) {
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, localRequest(t, http.MethodGet, "/revoke", ""))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rr.Code)
	}
}

// -----------------------------------------------------------------------
// localhostOnly — Unix socket connection (empty RemoteAddr)
// -----------------------------------------------------------------------

func TestLocalAPI_LocalhostOnly_EmptyRemoteAddr(t *testing.T) {
	// Simulate a Unix domain socket connection: RemoteAddr is empty.
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/uuid", bytes.NewBufferString(""))
	req.RemoteAddr = "" // Unix socket — empty RemoteAddr
	mux.ServeHTTP(rr, req)
	// Should be allowed through (not 403).
	if rr.Code == http.StatusForbidden {
		t.Fatal("Unix socket (empty RemoteAddr) should not be rejected by localhostOnly")
	}
	// Should get 200 with UUID.
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 for Unix socket", rr.Code)
	}
}

// -----------------------------------------------------------------------
// POST /sync — ledger API
// -----------------------------------------------------------------------

func TestLedgerAPI_Sync_POST_OK(t *testing.T) {
	svc, _ := newLedgerService(t)
	mux := api.NewLedgerMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, ledgerRequest(t, http.MethodPost, "/sync", "10.0.0.10:9999"))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /sync status %d, want 200", rr.Code)
	}
}

func TestLedgerAPI_Sync_MethodNotAllowed(t *testing.T) {
	svc, _ := newLedgerService(t)
	mux := api.NewLedgerMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/sync", "10.0.0.11:9999"))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /sync status %d, want 405", rr.Code)
	}
}

// -----------------------------------------------------------------------
// GET /q/{uuid} — empty uuid
// -----------------------------------------------------------------------

func TestLedgerAPI_Query_EmptyUUID(t *testing.T) {
	svc, _ := newLedgerService(t)
	mux := api.NewLedgerMux(svc)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, ledgerRequest(t, http.MethodGet, "/q/", "10.0.0.12:9999"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for empty UUID path", rr.Code)
	}
}

// -----------------------------------------------------------------------
// IPv6 loopback connection
// -----------------------------------------------------------------------

func TestLocalAPI_LocalhostOnly_IPv6Loopback(t *testing.T) {
	// ::1 is the IPv6 loopback address — should be allowed.
	svc, _ := newTestService(t)
	mux := api.NewLocalMux(svc)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/uuid", bytes.NewBufferString(""))
	req.RemoteAddr = "[::1]:54321"
	mux.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Error("IPv6 loopback ::1 should be allowed by localhostOnly")
	}
}
