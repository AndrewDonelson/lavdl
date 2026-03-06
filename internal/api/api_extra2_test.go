package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AndrewDonelson/ladl/internal/api"
	"github.com/AndrewDonelson/ladl/internal/format"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/ledger"
)

// TestLocalAPI_UUID_MethodNotAllowed verifies that a non-GET request to /uuid
// returns 405 Method Not Allowed.
func TestLocalAPI_UUID_MethodNotAllowed(t *testing.T) {
	dir := t.TempDir()
	led := ledger.NewMemLedger()
	defer led.Shutdown()

	svc := &api.LocalService{IdentityDir: dir, Ledger: led}
	mux := api.NewLocalMux(svc)

	req := httptest.NewRequest(http.MethodPost, "/uuid", nil)
	req.RemoteAddr = "127.0.0.1:0"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /uuid code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// TestLocalAPI_Status_MethodNotAllowed2 verifies that a non-GET request to /status
// returns 405 Method Not Allowed.
func TestLocalAPI_Status_MethodNotAllowed2(t *testing.T) {
	dir := t.TempDir()
	led := ledger.NewMemLedger()
	defer led.Shutdown()

	svc := &api.LocalService{IdentityDir: dir, Ledger: led}
	mux := api.NewLocalMux(svc)

	req := httptest.NewRequest(http.MethodPut, "/status", nil)
	req.RemoteAddr = "127.0.0.1:0"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT /status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// TestLocalAPI_Verify_Level1_UnknownGroup2 confirms that Level1 verification with an
// unknown group returns 400.
func TestLocalAPI_Verify_Level1_UnknownGroup2(t *testing.T) {
	dir := t.TempDir()
	led := ledger.NewMemLedger()
	defer led.Shutdown()

	svc := &api.LocalService{IdentityDir: dir, Ledger: led}
	mux := api.NewLocalMux(svc)

	body := bytes.NewBufferString(`{"group":"z","level":1}`)
	req := httptest.NewRequest(http.MethodPost, "/verify", body)
	req.RemoteAddr = "127.0.0.1:0"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("POST /verify unknown group code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestLocalAPI_Revoke_ConfirmFalse_JSON tests the confirm-false path.
func TestLocalAPI_Revoke_ConfirmFalse_JSON(t *testing.T) {
	dir := t.TempDir()
	led := ledger.NewMemLedger()
	defer led.Shutdown()

	svc := &api.LocalService{IdentityDir: dir, Ledger: led}
	mux := api.NewLocalMux(svc)

	body := bytes.NewBufferString(`{"confirm":false}`)
	req := httptest.NewRequest(http.MethodPost, "/revoke", body)
	req.RemoteAddr = "127.0.0.1:0"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("POST /revoke confirm=false code = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestLocalAPI_Status_WithLocalPayload verifies that handleStatus returns the
// two-byte local string when a record exists in the local ledger cache.
func TestLocalAPI_Status_WithLocalPayload(t *testing.T) {
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

	led := ledger.NewMemLedger()
	defer led.Shutdown()

	// Publish a record locally so LocalPayload returns it.
	p := format.VerificationPayload{G: "a", L: 1, T: time.Now().UTC().Format("2006-01")}
	_ = led.Publish(context.Background(), uid.UUID, p)

	svc := &api.LocalService{IdentityDir: dir, Ledger: led}
	mux := api.NewLocalMux(svc)

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.RemoteAddr = "127.0.0.1:0"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /status code = %d, want 200", rr.Code)
	}
	respBody := rr.Body.String()
	// local field should contain "a1"
	if !bytes.Contains([]byte(respBody), []byte("a1")) {
		t.Errorf("GET /status body %q should contain %q", respBody, "a1")
	}
}

// TestLocalAPI_Verify_Level2_WithDocumentPath tests that /verify with level=2
// and a document_path pointing to a nonexistent file returns 400 (OCR fails).
// This covers the opts + Level2 call + error return in handleVerify.
func TestLocalAPI_Verify_Level2_WithDocumentPath(t *testing.T) {
	dir := t.TempDir()
	pub, priv2, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Save(dir, pub, priv2); err != nil {
		t.Fatal(err)
	}

	led := ledger.NewMemLedger()
	defer led.Shutdown()

	svc := &api.LocalService{
		IdentityDir: dir,
		Ledger:      led,
		OCRPath:     "/nonexistent/tesseract",
	}
	mux := api.NewLocalMux(svc)

	body := bytes.NewBufferString(`{"group":"a","level":2,"document_path":"/tmp/nonexistent_ladl_test.jpg"}`)
	req := httptest.NewRequest(http.MethodPost, "/verify", body)
	req.RemoteAddr = "127.0.0.1:0"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Level2 will fail because tesseract does not exist or image does not exist.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("POST /verify level2 nonexistent doc code = %d, want 400", rr.Code)
	}
}
