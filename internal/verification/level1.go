// Package verification implements the three LADL verification levels.
//
// Level 1: Self-attestation — the user signs their own age group claim.
// Level 2: Document-assisted — DOB is extracted via OCR; an age group is derived.
// Level 3: W3C Verifiable Credential — a trusted issuer attests the age group.
package verification

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/AndrewDonelson/ladl/internal/format"
)

// Record is the universal output of any verification level.
// It carries the signed VerificationPayload plus metadata.
type Record struct {
	UUID    string // derived from the public key
	Payload format.VerificationPayload
	// UserSig is the base64url-encoded Ed25519 signature of the canonical
	// two-byte response, signed by the user's private key.
	UserSig string
}

// Level1 performs self-attestation: the user claims an age group and signs it.
// group must be one of "a", "b", "c", "d" (lowercase).
// Returns ErrInvalidAgeGroup if group is invalid.
func Level1(group, uuid string, priv ed25519.PrivateKey) (*Record, error) {
	if err := format.ValidateGroup(group); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	p := format.VerificationPayload{
		G: group,
		L: 1,
		T: now.Format("2006-01"),
	}

	twoBytes := format.FormatTwoBytes(p)
	sig := ed25519.Sign(priv, []byte(twoBytes))

	return &Record{
		UUID:    uuid,
		Payload: p,
		UserSig: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}
