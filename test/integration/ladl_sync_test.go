//go:build integration

package integration

import (
"context"
"testing"
"time"

"github.com/AndrewDonelson/ladl/internal/format"
"github.com/AndrewDonelson/ladl/internal/identity"
"github.com/AndrewDonelson/ladl/internal/ledger"
)

// TestIntegration_TwoMemLedgers_IndependentState verifies that two in-memory
// ledgers are independent (different state stores).
func TestIntegration_TwoMemLedgers_IndependentState(t *testing.T) {
led1 := ledger.NewMemLedger()
defer led1.Shutdown()
led2 := ledger.NewMemLedger()
defer led2.Shutdown()

pub, _, _ := identity.GenerateKeypair()
uuid := identity.DeriveUUID(pub)
payload := format.VerificationPayload{G: "d", L: 1, T: time.Now().Format("2006-01")}

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// Publish to led1.
if err := led1.Publish(ctx, uuid, payload); err != nil {
t.Fatalf("led1.Publish: %v", err)
}

// led1 should find it.
resp1, status1, err1 := led1.Query(ctx, uuid)
if err1 != nil {
t.Fatalf("led1.Query: %v", err1)
}
if status1 == ledger.StatusUnknown {
t.Error("led1: status should not be Unknown after publish")
}
_ = resp1

// led2 should NOT find it (independent state).
_, status2, _ := led2.Query(ctx, uuid)
if status2 != ledger.StatusUnknown {
t.Errorf("led2: expected StatusUnknown for uuid published to led1 only; got %v", status2)
}
}

// TestIntegration_PublishQueryRevoke_SingleLedger exercises the full lifecycle
// on a single in-memory ledger.
func TestIntegration_PublishQueryRevoke_SingleLedger(t *testing.T) {
led := ledger.NewMemLedger()
defer led.Shutdown()

pub, _, _ := identity.GenerateKeypair()
uuid := identity.DeriveUUID(pub)
payload := format.VerificationPayload{G: "c", L: 1, T: time.Now().Format("2006-01")}

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// Publish.
if err := led.Publish(ctx, uuid, payload); err != nil {
t.Fatalf("Publish: %v", err)
}

// Query — should find a result.
twoBytes, status, err := led.Query(ctx, uuid)
if err != nil {
t.Fatalf("Query after publish: %v", err)
}
if status == ledger.StatusUnknown {
t.Fatal("Query: status is Unknown despite successful Publish")
}
if len(twoBytes) == 0 {
t.Error("Query: empty two-byte response")
}

// Revoke.
if err := led.Revoke(ctx, uuid); err != nil {
t.Fatalf("Revoke: %v", err)
}

// Query again — should be revoked.
_, revokedStatus, revokedErr := led.Query(ctx, uuid)
if revokedStatus != ledger.StatusRevoked {
t.Errorf("post-revoke status = %v, want StatusRevoked (err=%v)", revokedStatus, revokedErr)
}
}

// TestIntegration_LocalPayload tests that LocalPayload returns the cached
// payload after Publish.
func TestIntegration_LocalPayload(t *testing.T) {
led := ledger.NewMemLedger()
defer led.Shutdown()

pub, _, _ := identity.GenerateKeypair()
uuid := identity.DeriveUUID(pub)
want := format.VerificationPayload{G: "b", L: 1, T: time.Now().Format("2006-01")}

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
if err := led.Publish(ctx, uuid, want); err != nil {
t.Fatalf("Publish: %v", err)
}

got, ok := led.LocalPayload(uuid)
if !ok {
t.Fatal("LocalPayload returned false after Publish")
}
if got.G != want.G || got.L != want.L {
t.Errorf("LocalPayload = %+v, want %+v", got, want)
}
}
