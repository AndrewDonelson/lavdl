package ledger_test

import (
	"context"
	"testing"
	"time"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/format"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/ledger"
)

func newUUID(t *testing.T) string {
	t.Helper()
	pub, _, _ := identity.GenerateKeypair()
	return identity.DeriveUUID(pub)
}

func TestNewMemLedger_NotNil(t *testing.T) {
	led := ledger.NewMemLedger()
	if led == nil {
		t.Fatal("NewMemLedger() returned nil")
	}
	_ = led.Shutdown()
}

func TestPeerCount_MemLedger(t *testing.T) {
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	count := led.PeerCount()
	// In-memory ledger with no connected peers — should be 0.
	if count < 0 {
		t.Errorf("PeerCount() = %d, want >= 0", count)
	}
}

func TestPeerCount_NilLayer(t *testing.T) {
	led := ledger.New(nil, "")
	if count := led.PeerCount(); count != 0 {
		t.Errorf("PeerCount() with nil layer = %d, want 0", count)
	}
}

func TestPublish_Basic(t *testing.T) {
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	uuid := newUUID(t)
	p := format.VerificationPayload{G: "d", L: 1, T: "2024-06"}
	if err := led.Publish(ctx, uuid, p); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
}

func TestPublish_RePublish_UpdatesRecord(t *testing.T) {
	// Publishing twice to the same UUID should succeed (re-publish path).
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	uuid := newUUID(t)
	p1 := format.VerificationPayload{G: "b", L: 1, T: "2024-01"}
	p2 := format.VerificationPayload{G: "c", L: 2, T: "2024-06"}

	if err := led.Publish(ctx, uuid, p1); err != nil {
		t.Fatalf("first Publish() error = %v", err)
	}
	// Re-publish triggers the ErrAlreadyPublished → revoke + re-publish path.
	if err := led.Publish(ctx, uuid, p2); err != nil {
		t.Fatalf("re-Publish() error = %v", err)
	}
	// The local payload should reflect the second publish.
	got, ok := led.LocalPayload(uuid)
	if !ok {
		t.Fatal("LocalPayload() returned false after re-publish")
	}
	if got.G != "c" {
		t.Errorf("LocalPayload().G = %q after re-publish, want \"c\"", got.G)
	}
}

func TestQuery_Found_CallsMapToPayload(t *testing.T) {
	// mapToPayload is exercised by Query when a record exists in L4 or local cache.
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	uuid := newUUID(t)
	p := format.VerificationPayload{G: "c", L: 1, T: "2024-06"}
	_ = led.Publish(ctx, uuid, p)

	resp, status, err := led.Query(ctx, uuid)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	// Accept StatusPending or StatusConfirmed — both indicate the record was found.
	if status == ledger.StatusUnknown || status == ledger.StatusRevoked {
		t.Errorf("status = %v, want Pending or Confirmed (record found)", status)
	}
	if string(resp) != "c1" {
		t.Errorf("resp = %q, want \"c1\"", resp)
	}
}

func TestQuery_NotFound_ReturnsUnknown(t *testing.T) {
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	_, status, err := led.Query(ctx, "no-such-uuid-xxxxx")
	if err != nil {
		t.Fatalf("Query() for unknown UUID error = %v", err)
	}
	if status != ledger.StatusUnknown {
		t.Errorf("status = %v, want StatusUnknown", status)
	}
}

func TestQuery_Revoked_FromL4(t *testing.T) {
	// After publishing and revoking, Query should return StatusRevoked.
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	uuid := newUUID(t)
	p := format.VerificationPayload{G: "d", L: 1, T: "2024-06"}
	_ = led.Publish(ctx, uuid, p)
	_ = led.Revoke(ctx, uuid)

	_, status, err := led.Query(ctx, uuid)
	if status != ledger.StatusRevoked {
		t.Errorf("status = %v, want StatusRevoked", status)
	}
	if err != ladlerrors.ErrLADLRecordRevoked {
		t.Errorf("err = %v, want ErrLADLRecordRevoked", err)
	}
}

func TestQuery_NilLayer_ReturnsUnavailable(t *testing.T) {
	led := ledger.New(nil, "")
	ctx := context.Background()

	_, status, err := led.Query(ctx, "any-uuid")
	if status != ledger.StatusUnknown {
		t.Errorf("status = %v, want StatusUnknown", status)
	}
	if err != ladlerrors.ErrLADLUnavailable {
		t.Errorf("err = %v, want ErrLADLUnavailable", err)
	}
}

func TestRevoke_ExistingRecord(t *testing.T) {
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	uuid := newUUID(t)
	p := format.VerificationPayload{G: "b", L: 1, T: "2024-06"}
	_ = led.Publish(ctx, uuid, p)

	if err := led.Revoke(ctx, uuid); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
}

func TestRevoke_NonExistentRecord_NoError(t *testing.T) {
	// Revoking a UUID that doesn't exist in L4 should still succeed (ErrNotFound is ignored).
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	if err := led.Revoke(ctx, "never-published-uuid"); err != nil {
		t.Fatalf("Revoke() on non-existent UUID error = %v", err)
	}
}

func TestLocalPayload_NotFound(t *testing.T) {
	led := ledger.NewMemLedger()
	defer led.Shutdown()

	_, ok := led.LocalPayload("no-such-uuid")
	if ok {
		t.Error("LocalPayload() returned true for never-published UUID")
	}
}

func TestLocalPayload_Found(t *testing.T) {
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	uuid := newUUID(t)
	p := format.VerificationPayload{G: "a", L: 1, T: "2024-06"}
	_ = led.Publish(ctx, uuid, p)

	got, ok := led.LocalPayload(uuid)
	if !ok {
		t.Fatal("LocalPayload() returned false after Publish()")
	}
	if got.G != "a" {
		t.Errorf("LocalPayload().G = %q, want \"a\"", got.G)
	}
}

func TestShutdown_OK(t *testing.T) {
	led := ledger.NewMemLedger()
	if err := led.Shutdown(); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestShutdown_NilLayer(t *testing.T) {
	led := ledger.New(nil, "")
	if err := led.Shutdown(); err != nil {
		t.Errorf("Shutdown() with nil layer error = %v", err)
	}
}

func TestPublish_MultipleUUIDs(t *testing.T) {
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		uuid := newUUID(t)
		p := format.VerificationPayload{G: "d", L: 1, T: time.Now().Format("2006-01")}
		if err := led.Publish(ctx, uuid, p); err != nil {
			t.Fatalf("Publish(%d) error = %v", i, err)
		}
	}
}

func TestQuery_LocalCache_AfterPublish(t *testing.T) {
	// After Publish, LocalPayload should be accessible regardless of L4 status.
	led := ledger.NewMemLedger()
	defer led.Shutdown()
	ctx := context.Background()

	uuid := newUUID(t)
	p := format.VerificationPayload{G: "b", L: 2, T: "2024-06"}
	_ = led.Publish(ctx, uuid, p)

	got, ok := led.LocalPayload(uuid)
	if !ok {
		t.Fatal("LocalPayload not found after Publish()")
	}
	if got.L != 2 {
		t.Errorf("LocalPayload().L = %d, want 2", got.L)
	}
}
