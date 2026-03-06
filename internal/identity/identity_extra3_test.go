package identity_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/identity"
)

// TestExport_IdentityNotFound covers the Load-failure return in Export
// when the identity directory does not contain any key files.
func TestExport_IdentityNotFound(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "backup.key")
	// dir has no identity files → Load returns ErrIdentityNotFound → Export returns that error.
	err := identity.Export(dir, outPath, "passphrase")
	if err == nil {
		t.Error("expected Export to fail when identity directory is empty")
	}
}

// TestExport_WriteFileFails covers the os.MkdirAll / os.WriteFile failure path
// in Export when the output parent directory is not writable.
func TestExport_WriteFileFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}

	srcDir := t.TempDir()
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Save(srcDir, pub, priv); err != nil {
		t.Fatal(err)
	}

	// outPath is inside a read-only parent → MkdirAll or WriteFile fails.
	readOnlyDir := t.TempDir()
	if err := os.Chmod(readOnlyDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(readOnlyDir, 0700) })

	outPath := filepath.Join(readOnlyDir, "subdir", "backup.key")
	err = identity.Export(srcDir, outPath, "passphrase")
	if err == nil {
		t.Error("expected Export to fail when output path is in a read-only directory")
	}
}

// TestImport_WrongPassphrase covers the gcm.Open failure path in Import:
// when the passphrase is wrong, AES-GCM authentication fails → ErrDecryptionFailed.
func TestImport_WrongPassphrase(t *testing.T) {
	srcDir := t.TempDir()
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Save(srcDir, pub, priv); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(t.TempDir(), "backup.key")
	if err := identity.Export(srcDir, backupPath, "correct-passphrase"); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	dstDir := t.TempDir()
	_, err = identity.Import(dstDir, backupPath, "wrong-passphrase", false)
	if err == nil {
		t.Error("expected Import to fail with wrong passphrase")
	}
}

// TestImport_SaveFails covers the Save-failure path in Import (line 124-126):
// when decryption succeeds but Save cannot write the key files to the destination dir.
func TestImport_SaveFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}

	srcDir := t.TempDir()
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Save(srcDir, pub, priv); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(t.TempDir(), "backup.key")
	if err := identity.Export(srcDir, backupPath, "p4$$phrase"); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Make the destination dir read-only so Save fails inside Import.
	dstDir := t.TempDir()
	if err := os.Chmod(dstDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dstDir, 0700) })

	_, err = identity.Import(dstDir, backupPath, "p4$$phrase", false)
	if err == nil {
		t.Error("expected Import to fail when destination directory is read-only")
	}
}
