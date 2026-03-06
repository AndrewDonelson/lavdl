// level3.go — Verifiable Credential (W3C VC) verification — Level 3.
//
// This is a placeholder implementation. It parses a W3C VC JSON-LD document,
// verifies the issuer's Ed25519 signature using the public DID in the issuer field,
// extracts the age claim, and records l:3 in the payload.
// No VC content is sent to the LADL.
package verification

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/format"
)

// VC is the minimal parseable structure of a W3C Verifiable Credential.
type VC struct {
	Context           []interface{}          `json:"@context"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      string                 `json:"issuanceDate"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             VCProof                `json:"proof"`
}

// VCProof is the cryptographic proof attached to a W3C VC.
type VCProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	JWSSignature       string `json:"jws"`
}

// Level3 performs a Verifiable Credential verification.
//
// It parses the VC JSON, verifies the issuer's signature, extracts an age claim,
// and returns a signed Record with level 3.
func Level3(vcJSON []byte, uuid string, priv ed25519.PrivateKey, referenceDate *time.Time) (*Record, error) {
	var vc VC
	if err := json.Unmarshal(vcJSON, &vc); err != nil {
		return nil, fmt.Errorf("parse VC: %w", err)
	}

	// Verify the issuer signature.
	if err := verifyVCSignature(&vc, vcJSON); err != nil {
		return nil, err
	}

	// Extract age claim from credentialSubject.
	group, err := extractAgeClaimFromVC(&vc, referenceDate)
	if err != nil {
		return nil, err
	}

	var ref time.Time
	if referenceDate != nil {
		ref = *referenceDate
	} else {
		ref = time.Now().UTC()
	}

	payload := format.VerificationPayload{
		G: group,
		L: 3,
		T: ref.Format("2006-01"),
	}

	sig, err := signPayload(priv, uuid, payload)
	if err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}

	return &Record{
		UUID:    uuid,
		Payload: payload,
		UserSig: sig,
	}, nil
}

// verifyVCSignature verifies the Ed25519 signature on the VC.
// Two signature encodings are supported:
//
//  1. Raw base64url signature (no dots): the signature covers the VC JSON with
//     the "proof" field removed.
//  2. JWS compact serialisation (base64url.base64url.base64url): the signature
//     covers header + "." + base64url(vc-without-proof).
func verifyVCSignature(vc *VC, rawJSON []byte) error {
	if vc.Proof.Type == "" || vc.Proof.JWSSignature == "" {
		return ladlerrors.ErrVCInvalidSignature
	}

	issuerPub, err := resolveIssuerKey(vc.Issuer)
	if err != nil {
		// Preserve the descriptive error for non-did:key issuers.
		return err
	}

	// Reconstruct the VC without the proof field for verification.
	withoutProof, err := removeProofField(rawJSON)
	if err != nil {
		return ladlerrors.ErrVCInvalidSignature
	}

	jws := vc.Proof.JWSSignature
	parts := strings.Split(jws, ".")

	switch len(parts) {
	case 1:
		// Raw base64url signature — covers the VC JSON without "proof".
		sigBytes, decErr := base64.RawURLEncoding.DecodeString(jws)
		if decErr != nil {
			return ladlerrors.ErrVCInvalidSignature
		}
		if !ed25519.Verify(issuerPub, withoutProof, sigBytes) {
			return ladlerrors.ErrVCInvalidSignature
		}

	case 3:
		// JWS compact: header.payload.signature — payload is detached.
		// Signed message: base64url(header) + "." + base64url(vc-without-proof).
		sigBytes, decErr := base64.RawURLEncoding.DecodeString(parts[2])
		if decErr != nil {
			return ladlerrors.ErrVCInvalidSignature
		}
		msg := buildSignedBytes(parts[0], withoutProof)
		if !ed25519.Verify(issuerPub, msg, sigBytes) {
			return ladlerrors.ErrVCInvalidSignature
		}

	default:
		return ladlerrors.ErrVCInvalidSignature
	}

	return nil
}

// removeProofField parses vcJSON, removes the "proof" key, and re-marshals to
// canonical JSON (Go's json.Marshal sorts map keys alphabetically).
func removeProofField(vcJSON []byte) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(vcJSON, &m); err != nil {
		return nil, err
	}
	delete(m, "proof")
	return json.Marshal(m)
}

// buildSignedBytes builds the JWS signing input from the header and the
// VC-without-proof payload.
func buildSignedBytes(headerB64 string, withoutProof []byte) []byte {
	payload := base64.RawURLEncoding.EncodeToString(withoutProof)
	return []byte(headerB64 + "." + payload)
}

// resolveIssuerKey extracts the Ed25519 public key from a did:key DID.
//
// Supported formats:
//   - did:key:<base64url(32-byte Ed25519 public key)>  — used in tests
//   - did:key:z6Mk<hex64>                              — hex-encoded Ed25519 key
func resolveIssuerKey(issuer string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(issuer, "did:key:") {
		return nil, fmt.Errorf("unsupported DID method: only did:key is supported, got %s", issuer)
	}

	encoded := strings.TrimPrefix(issuer, "did:key:")

	// Try direct base64url decode first (32 bytes → 43 chars base64url).
	if raw, err := base64.RawURLEncoding.DecodeString(encoded); err == nil && len(raw) == 32 {
		return ed25519.PublicKey(raw), nil
	}

	// Try multibase base58btc (z prefix) + hex convention.
	if len(encoded) > 1 && encoded[0] == 'z' {
		hexPart := encoded[1:]
		if len(hexPart) == 64 {
			keyBytes, err := hex.DecodeString(hexPart)
			if err == nil && len(keyBytes) == 32 {
				return ed25519.PublicKey(keyBytes), nil
			}
		}
	}

	return nil, fmt.Errorf("cannot resolve ed25519 key from did:key DID: %s", issuer)
}

// extractAgeClaimFromVC extracts an age group from the VC's credentialSubject.
// It looks for "ageGroup", "birthDate", "minimumAge", or "ageOver*" claims.
func extractAgeClaimFromVC(vc *VC, referenceDate *time.Time) (string, error) {
	subj := vc.CredentialSubject

	// Direct age group claim.
	if g, ok := subj["ageGroup"].(string); ok {
		if err := format.ValidateGroup(g); err == nil {
			return g, nil
		}
	}

	// birthDate claim → compute group.
	if bd, ok := subj["birthDate"].(string); ok {
		dob, err := parseDateString(bd)
		if err == nil {
			var ref time.Time
			if referenceDate != nil {
				ref = *referenceDate
			} else {
				ref = time.Now().UTC()
			}
			return ageGroupFromDOB(dob, ref), nil
		}
	}

	// minimumAge claim (integer) → map to group.
	if ma, ok := subj["minimumAge"].(float64); ok {
		switch {
		case ma >= 21:
			return "d", nil
		case ma >= 18:
			return "c", nil
		case ma >= 13:
			return "b", nil
		default:
			return "a", nil
		}
	}

	// ageOver (boolean flags per threshold).
	if over18, ok := subj["ageOver18"].(bool); ok && over18 {
		if over21, ok2 := subj["ageOver21"].(bool); ok2 && over21 {
			return "d", nil
		}
		return "c", nil
	}

	return "", ladlerrors.ErrVCMissingAgeClaim
}
