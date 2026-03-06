package identity_test

import (
	"os"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/identity"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

func TestExportEncrypts(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(dir, pub, priv)

	outPath := dir + "/backup.key"
	if err := identity.Export(dir, outPath, "test-passphrase"); err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	// The backup file must not be the raw private key seed.
	data, _ := os.ReadFile(outPath)
	seed := priv.Seed()
	if string(data) == string(seed) {
		t.Error("backup file appears to be plain (unencrypted) seed bytes")
	}
}

func TestImportDecrypts(t *testing.T) {
	srcDir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(srcDir, pub, priv)

	outPath := srcDir + "/backup.key"
	if err := identity.Export(srcDir, outPath, "secret"); err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	dstDir := t.TempDir()
	uid, err := identity.Import(dstDir, outPath, "secret", false)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	_, loadPub, loadPriv, lerr := identity.Load(dstDir)
	if lerr != nil {
		t.Fatalf("Load() after Import() error = %v", lerr)
	}

	if string(priv.Seed()) != string(loadPriv.Seed()) {
		t.Error("imported private key seed does not match original")
	}
	if string(pub) != string(loadPub) {
		t.Error("imported public key does not match original")
	}
	_ = uid
}

func TestImportWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(dir, pub, priv)

	outPath := dir + "/backup.key"
	_ = identity.Export(dir, outPath, "correct-pass")

	dstDir := t.TempDir()
	_, err := identity.Import(dstDir, outPath, "wrong-pass", false)
	if err != ladlerrors.ErrDecryptionFailed {
		t.Errorf("got %v, want ErrDecryptionFailed", err)
	}
}

func TestExportImport_UUIDPreserved(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(dir, pub, priv)

	originalUUID := identity.DeriveUUID(pub)

	outPath := dir + "/backup.key"
	_ = identity.Export(dir, outPath, "pw")

	dstDir := t.TempDir()
	uid, err := identity.Import(dstDir, outPath, "pw", false)
	if err != nil {
		t.Fatal(err)
	}

	if uid.UUID != originalUUID {
		t.Errorf("UUID after import = %s, want %s", uid.UUID, originalUUID)
	}
}

func TestExport_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(dir, pub, priv)

	outPath := dir + "/my-backup.key"
	_ = identity.Export(dir, outPath, "pw")

	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("export file was not created")
	}
}

func TestImport_OverwriteExisting(t *testing.T) {
	// Source identity to export.
	srcDir := t.TempDir()
	pub, priv, _ := identity.GenerateKeypair()
	_ = identity.Save(srcDir, pub, priv)
	outPath := srcDir + "/backup.key"
	_ = identity.Export(srcDir, outPath, "pw")

	// Destination already has an identity.
	dstDir := t.TempDir()
	pub2, priv2, _ := identity.GenerateKeypair()
	_ = identity.Save(dstDir, pub2, priv2)

	// Import with overwrite=false should return ErrIdentityExists.
	_, err := identity.Import(dstDir, outPath, "pw", false)
	if err != ladlerrors.ErrIdentityExists {
		t.Errorf("got %v, want ErrIdentityExists (overwrite=false)", err)
	}

	// Import with overwrite=true should succeed.
	uid, err := identity.Import(dstDir, outPath, "pw", true)
	if err != nil {
		t.Fatalf("Import with overwrite=true error = %v", err)
	}
	if uid.UUID != identity.DeriveUUID(pub) {
		t.Error("overwrite import produced wrong UUID")
	}
}
