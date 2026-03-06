package identity_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/identity"
	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

func TestConfigDir_NotEmpty(t *testing.T) {
	dir := identity.ConfigDir()
	if dir == "" {
		t.Error("ConfigDir() returned empty string")
	}
}

func TestConfigDir_EndsWithLadl(t *testing.T) {
	dir := identity.ConfigDir()
	if !strings.HasSuffix(dir, "ladl") {
		t.Errorf("ConfigDir() = %q, expected to end with \"ladl\"", dir)
	}
}

func TestConfigDir_ContainsDotConfig(t *testing.T) {
	dir := identity.ConfigDir()
	if !strings.Contains(dir, ".config") {
		t.Errorf("ConfigDir() = %q, expected to contain \".config\"", dir)
	}
}

func TestExists_False_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	if identity.Exists(dir) {
		t.Error("Exists() returned true for empty dir")
	}
}

func TestExists_True_AfterSave(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(dir, pub, priv)
	if !identity.Exists(dir) {
		t.Error("Exists() returned false after Save()")
	}
}

func TestExists_False_NonExistentDir(t *testing.T) {
	if identity.Exists("/totally/nonexistent/path/ladl-identity") {
		t.Error("Exists() returned true for non-existent dir")
	}
}

func TestLoad_MissingPubKey(t *testing.T) {
	// Write only the priv key — no pub key file.
	dir := t.TempDir()
	_, priv, _ := identity.GenerateKeypair()
	privPath := filepath.Join(dir, "identity.priv")
	if err := os.WriteFile(privPath, []byte(priv), 0600); err != nil {
		t.Fatal(err)
	}
	// Do NOT write identity.pub.
	_, _, _, err := identity.Load(dir)
	if err != ladlerrors.ErrIdentityNotFound {
		t.Errorf("got %v, want ErrIdentityNotFound (missing pub key)", err)
	}
}

func TestSave_MkdirAll_SubDir(t *testing.T) {
	// Save into a nested subdirectory that does not yet exist.
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b", "c")
	pub, priv, _ := identity.GenerateKeypair()
	if err := identity.Save(dir, pub, priv); err != nil {
		t.Fatalf("Save() to nested dir error = %v", err)
	}
	if !identity.Exists(dir) {
		t.Error("identity not found after Save() to nested dir")
	}
}

func TestLoad_PrivKeyReadError(t *testing.T) {
	// Create dir with priv key that becomes unreadable after stat.
	dir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(dir, pub, priv)

	privPath := filepath.Join(dir, "identity.priv")
	// Change permissions so stat succeeds (perm=0600) but read fails.
	os.Chmod(privPath, 0000)
	defer os.Chmod(privPath, 0600)

	_, _, _, err := identity.Load(dir)
	// Should get either permission error or identity error — not nil.
	if err == nil {
		t.Error("Load() should fail with unreadable priv key")
	}
}

func TestImport_ReadBackupError(t *testing.T) {
	dstDir := t.TempDir()
	_, err := identity.Import(dstDir, "/nonexistent/backup-xyz.key", "pw", false)
	if err == nil {
		t.Error("Import() with nonexistent backup should return error")
	}
}

func TestImport_InvalidBackupJSON(t *testing.T) {
	dstDir := t.TempDir()
	tmpBackup := filepath.Join(t.TempDir(), "backup.key")
	_ = os.WriteFile(tmpBackup, []byte("not json {{{"), 0600)
	_, err := identity.Import(dstDir, tmpBackup, "pw", false)
	if err == nil {
		t.Error("Import() with invalid JSON backup should return error")
	}
}
