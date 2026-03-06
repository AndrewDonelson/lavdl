package identity_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/identity"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

func TestGenerateKeypair(t *testing.T) {
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	if len(pub) == 0 {
		t.Error("public key is empty")
	}
	if len(priv) == 0 {
		t.Error("private key is empty")
	}
}

func TestDeriveUUID_Deterministic(t *testing.T) {
	pub, _, _ := identity.GenerateKeypair()
	u1 := identity.DeriveUUID(pub)
	u2 := identity.DeriveUUID(pub)
	if u1 != u2 {
		t.Errorf("DeriveUUID not deterministic: %s != %s", u1, u2)
	}
}

func TestDeriveUUID_Unique(t *testing.T) {
	pub1, _, _ := identity.GenerateKeypair()
	pub2, _, _ := identity.GenerateKeypair()
	u1 := identity.DeriveUUID(pub1)
	u2 := identity.DeriveUUID(pub2)
	if u1 == u2 {
		t.Error("DeriveUUID produced identical UUIDs for different keys")
	}
}

func TestDeriveUUID_Format(t *testing.T) {
	pub, _, _ := identity.GenerateKeypair()
	u := identity.DeriveUUID(pub)
	if len(u) != 36 {
		t.Errorf("UUID length = %d, want 36", len(u))
	}
	if u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
		t.Errorf("UUID dashes not in expected positions: %s", u)
	}
}

func TestSaveLoadIdentity(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Save(dir, pub, priv); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	uid, loadPub, loadPriv, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(pub) != string(loadPub) {
		t.Error("public key round-trip mismatch")
	}
	if string(priv.Seed()) != string(loadPriv.Seed()) {
		t.Error("private key seed round-trip mismatch")
	}
	if uid.UUID == "" {
		t.Error("loaded UUID is empty")
	}
	expectedUUID := identity.DeriveUUID(pub)
	if uid.UUID != expectedUUID {
		t.Errorf("UUID mismatch: got %s, want %s", uid.UUID, expectedUUID)
	}
}

func TestLoadIdentity_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, _, _, err := identity.Load(dir)
	if err != ladlerrors.ErrIdentityNotFound {
		t.Errorf("got %v, want ErrIdentityNotFound", err)
	}
}

func TestLoadIdentity_WrongPermissions(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(dir, pub, priv)
	keyPath := filepath.Join(dir, "identity.priv")
	_ = os.Chmod(keyPath, 0644)
	_, _, _, err := identity.Load(dir)
	if err != ladlerrors.ErrInsecurePermissions {
		t.Errorf("got %v, want ErrInsecurePermissions", err)
	}
}

func TestSystemBinding_UniquePerUID(t *testing.T) {
	h1, err := identity.SystemBinding(1000)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := identity.SystemBinding(1001)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("SystemBinding produced identical hashes for UID 1000 and 1001")
	}
}

func TestSystemBinding_Deterministic(t *testing.T) {
	h1, _ := identity.SystemBinding(1000)
	h2, _ := identity.SystemBinding(1000)
	if h1 != h2 {
		t.Error("SystemBinding is not deterministic for same UID")
	}
}

func TestDeriveUUID_TypeAssertion(t *testing.T) {
	pub, _, _ := identity.GenerateKeypair()
	var epk ed25519.PublicKey = pub
	u := identity.DeriveUUID(epk)
	if len(u) != 36 {
		t.Errorf("UUID from explicit ed25519.PublicKey has length %d", len(u))
	}
}
