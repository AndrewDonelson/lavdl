package verification_test

import (
	"regexp"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/format"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/verification"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

func newTestIdentity(t *testing.T) (string, interface{ Seed() []byte }) {
	t.Helper()
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return identity.DeriveUUID(pub), priv
}

func TestLevel1_ValidGroup_D(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)
	rec, err := verification.Level1("d", uuid, priv)
	if err != nil {
		t.Fatalf("Level1() error = %v", err)
	}
	if rec.Payload.G != "d" {
		t.Errorf("Payload.G = %q, want %q", rec.Payload.G, "d")
	}
	if rec.Payload.L != 1 {
		t.Errorf("Payload.L = %d, want 1", rec.Payload.L)
	}
}

func TestLevel1_AllGroups(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)
	for _, g := range []string{"a", "b", "c", "d"} {
		rec, err := verification.Level1(g, uuid, priv)
		if err != nil {
			t.Errorf("Level1(%q) error = %v", g, err)
			continue
		}
		if rec.Payload.G != g {
			t.Errorf("Level1(%q) Payload.G = %q", g, rec.Payload.G)
		}
	}
}

func TestLevel1_InvalidGroup(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)
	_, err := verification.Level1("x", uuid, priv)
	if err != ladlerrors.ErrInvalidAgeGroup {
		t.Errorf("got %v, want ErrInvalidAgeGroup", err)
	}
}

func TestLevel1_UppercaseRejected(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)
	_, err := verification.Level1("D", uuid, priv)
	if err != ladlerrors.ErrInvalidAgeGroup {
		t.Errorf("uppercase group 'D': got %v, want ErrInvalidAgeGroup", err)
	}
}

func TestLevel1_EmptyGroup(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)
	_, err := verification.Level1("", uuid, priv)
	if err != ladlerrors.ErrInvalidAgeGroup {
		t.Errorf("empty group: got %v, want ErrInvalidAgeGroup", err)
	}
}

func TestLevel1_TimestampFormat(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)
	rec, err := verification.Level1("d", uuid, priv)
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := regexp.MatchString(`^\d{4}-\d{2}$`, rec.Payload.T)
	if !matched {
		t.Errorf("timestamp %q does not match YYYY-MM format", rec.Payload.T)
	}
}

func TestLevel1_ProducesSignedRecord(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)
	rec, err := verification.Level1("d", uuid, priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.UserSig) == 0 {
		t.Error("UserSig is empty; expected a valid Ed25519 signature")
	}
}

func TestLevel1_TwoByte_Output(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)
	rec, err := verification.Level1("d", uuid, priv)
	if err != nil {
		t.Fatal(err)
	}
	got := format.FormatTwoBytes(rec.Payload)
	if got != "d1" {
		t.Errorf("FormatTwoBytes = %q, want %q", got, "d1")
	}
}

// Ensure newTestIdentity helper compiles (it provides a priv interface used by Level2/3).
var _ = newTestIdentity
