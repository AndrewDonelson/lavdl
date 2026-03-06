package identity_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/identity"
)

// TestSave_MkdirAll_Fails verifies that Save returns an error when the parent
// directory is not writable (so MkdirAll for a new subdirectory fails).
func TestSave_MkdirAll_Fails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write anywhere — test not meaningful for root")
	}

	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	// Remove write permission so MkdirAll(subdir) will fail.
	if err := os.Chmod(base, 0500); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	t.Cleanup(func() { os.Chmod(base, 0700) })

	subdir := filepath.Join(base, "child_ladl_test")
	if err := identity.Save(subdir, pub, priv); err == nil {
		t.Error("Save succeeded unexpectedly on non-writable parent dir")
	}
}

// TestSave_WritePrivKey_Fails verifies that Save returns an error when the
// directory exists but is not writable (WriteFile priv key fails).
func TestSave_WritePrivKey_Fails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write anywhere — test not meaningful for root")
	}

	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// Existing dir — MkdirAll will succeed, but WriteFile will fail.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	if err := identity.Save(dir, pub, priv); err == nil {
		t.Error("Save succeeded unexpectedly on read-only dir")
	}
}

// TestLoad_StatNonNotExistError covers the path in Load where os.Stat returns
// an error that is NOT os.ErrNotExist (e.g., EACCES).
// Triggered by making the identity directory untraversable (mode 0000).
func TestLoad_StatNonNotExistError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}

	dir := t.TempDir()
	// Remove all permissions so os.Stat of any child path returns EACCES.
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	_, _, _, err := identity.Load(dir)
	if err == nil {
		t.Error("expected Load to fail when directory is untraversable")
	}
}

// TestLoad_ReadFilePubKeyNonNotExistError covers the path in Load where
// os.ReadFile on the public key file returns a non-NotExist error.
// Triggered by creating the pub key path as a directory instead of a file.
func TestLoad_ReadFilePubKeyNonNotExistError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}

	dir := t.TempDir()

	// Write a valid-length private key file with secure permissions (0600).
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Save normally first so both files exist.
	if err := identity.Save(dir, pub, priv); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Replace the public key file with a directory — ReadFile will fail with EISDIR.
	pubPath := filepath.Join(dir, "identity.pub")
	if err := os.Remove(pubPath); err != nil {
		t.Fatalf("remove pubkey: %v", err)
	}
	if err := os.MkdirAll(pubPath, 0755); err != nil {
		t.Fatalf("mkdir pubPath: %v", err)
	}

	_, _, _, err = identity.Load(dir)
	if err == nil {
		t.Error("expected Load to fail when pubkey path is a directory")
	}
}
