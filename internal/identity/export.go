// Package identity — export.go implements AES-256-GCM encrypted keypair backup/restore.
package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"golang.org/x/crypto/pbkdf2"
)

// exportedKey is the JSON structure written to the backup file.
type exportedKey struct {
	Version    int    `json:"version"`
	UUID       string `json:"uuid"`
	Salt       []byte `json:"salt"`   // PBKDF2 salt
	Nonce      []byte `json:"nonce"`  // AES-GCM nonce
	CipherText []byte `json:"cipher"` // encrypted seed
}

const exportVersion = 1

// Export encrypts the private key from dir with passphrase and writes the
// result to outPath. The file is self-contained: it includes the PBKDF2 salt
// and GCM nonce so that Import needs only the passphrase.
func Export(dir, outPath, passphrase string) error {
	_, pub, priv, err := Load(dir)
	if err != nil {
		return err
	}

	seed := priv.Seed()
	uuid := DeriveUUID(pub)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ct := gcm.Seal(nil, nonce, seed, nil)

	ek := exportedKey{
		Version:    exportVersion,
		UUID:       uuid,
		Salt:       salt,
		Nonce:      nonce,
		CipherText: ct,
	}

	data, err := json.Marshal(ek)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outPath, data, 0600)
}

// Import decrypts the keypair from backupPath using passphrase and installs it
// into dir, restoring the identity.
//
// If an identity already exists in dir and overwrite is false, returns ErrIdentityExists.
func Import(dir, backupPath, passphrase string, overwrite bool) (*UserIdentity, error) {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("read backup: %w", err)
	}

	var ek exportedKey
	if err := json.Unmarshal(data, &ek); err != nil {
		return nil, fmt.Errorf("parse backup: %w", err)
	}

	// Check for existing identity.
	if identityExists(dir) && !overwrite {
		return nil, ladlerrors.ErrIdentityExists
	}

	key := deriveKey(passphrase, ek.Salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ladlerrors.ErrDecryptionFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ladlerrors.ErrDecryptionFailed
	}

	seed, err := gcm.Open(nil, ek.Nonce, ek.CipherText, nil)
	if err != nil {
		return nil, ladlerrors.ErrDecryptionFailed
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	if err := Save(dir, pub, priv); err != nil {
		return nil, fmt.Errorf("install keypair: %w", err)
	}

	uid := &UserIdentity{
		UUID: DeriveUUID(pub),
	}
	return uid, nil
}

// Exists reports whether an identity is present at dir.
func Exists(dir string) bool {
	return identityExists(dir)
}

// identityExists returns true if an identity already exists at dir.
func identityExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, privKeyFile))
	return err == nil
}

// deriveKey uses PBKDF2-SHA256 to derive a 32-byte AES key from a passphrase.
func deriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, 100_000, 32, sha256.New)
}
