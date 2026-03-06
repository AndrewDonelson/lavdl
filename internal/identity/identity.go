// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// identity.go — Ed25519 keypair generation, UUID derivation, load/save, and system binding

// Package identity manages Ed25519 keypairs and UUID derivation for LADL.
//
// Each user has exactly one keypair. The UUID is derived deterministically
// from the public key using SHA-256 and formatted as RFC 4122 UUID.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

const (
	privKeyFile = "identity.priv"
	pubKeyFile  = "identity.pub"
)

// UserIdentity holds the derived UUID (not the keypair itself).
type UserIdentity struct {
	UUID string
}

// GenerateKeypair creates a new Ed25519 keypair.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// DeriveUUID deterministically derives an RFC 4122 UUID from a public key.
// It uses the first 16 bytes of SHA-256(pubkey).
func DeriveUUID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	b := h[:16]
	// Set version 4 bits and variant bits for RFC 4122 compliance.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Save persists the keypair to dir.
// private key: mode 0600, public key: mode 0644.
func Save(dir string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	privPath := filepath.Join(dir, privKeyFile)
	if err := os.WriteFile(privPath, []byte(priv), 0600); err != nil {
		return err
	}
	pubPath := filepath.Join(dir, pubKeyFile)
	return os.WriteFile(pubPath, []byte(pub), 0644)
}

// Load reads the keypair from dir and returns the UserIdentity, public key,
// private key, and an error.
// Returns ErrIdentityNotFound if either file does not exist.
// Returns ErrInsecurePermissions if the private key file has world/group bits set.
func Load(dir string) (*UserIdentity, ed25519.PublicKey, ed25519.PrivateKey, error) {
	privPath := filepath.Join(dir, privKeyFile)
	pubPath := filepath.Join(dir, pubKeyFile)

	// Check permissions on private key.
	info, err := os.Stat(privPath)
	if os.IsNotExist(err) {
		return nil, nil, nil, ladlerrors.ErrIdentityNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, nil, nil, ladlerrors.ErrInsecurePermissions
	}

	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, nil, err
	}
	pubBytes, err := os.ReadFile(pubPath)
	if os.IsNotExist(err) {
		return nil, nil, nil, ladlerrors.ErrIdentityNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}

	priv := ed25519.PrivateKey(privBytes)
	pub := ed25519.PublicKey(pubBytes)
	uuid := DeriveUUID(pub)
	return &UserIdentity{UUID: uuid}, pub, priv, nil
}

// ConfigDir returns the default ~/.config/ladl directory.
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "ladl")
}

// SystemBinding returns a stable string derived from the user's UID and
// machine ID, used for adding context to verification records.
func SystemBinding(uid int) (string, error) {
	machineID := ""
	data, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		machineID = string(data)
	}
	salt := "ladl-v1"
	combined := fmt.Sprintf("%d|%s|%s", uid, machineID, salt)
	h := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", h[:8]), nil
}
