package verification_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/verification"
)

// buildVC creates a minimal W3C VC with the given age group and issuer DID,
// signed with issuerPriv (ed25519).
func buildVC(t *testing.T, ageGroup string, issuePub ed25519.PublicKey, issuePriv ed25519.PrivateKey) []byte {
	t.Helper()

	holder, _, _ := identity.GenerateKeypair()
	holderDID := "did:key:" + base64.RawURLEncoding.EncodeToString(holder)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vc := map[string]interface{}{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential", "AgeCredential"},
		"issuer":   issuerDID,
		"issued":   "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":       holderDID,
			"ageGroup": ageGroup,
		},
	}

	// Build signing payload (canonical JSON of vc minus proof).
	payload, err := json.Marshal(vc)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(issuePriv, payload)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	vc["proof"] = map[string]interface{}{
		"type":               "Ed25519Signature2020",
		"created":            "2024-01-01T00:00:00Z",
		"verificationMethod": issuerDID,
		"jws":                sigB64,
	}

	out, err := json.Marshal(vc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLevel3_ValidVC(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	vcJSON := buildVC(t, "d", issuePub, issuePriv)
	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() error = %v", err)
	}
	if rec.Payload.G != "d" {
		t.Errorf("group = %q, want %q", rec.Payload.G, "d")
	}
	if rec.Payload.L != 3 {
		t.Errorf("Payload.L = %d, want 3", rec.Payload.L)
	}
}

func TestLevel3_InvalidSignature(t *testing.T) {
	issuePub, _, _ := identity.GenerateKeypair()
	_, wrongPriv, _ := identity.GenerateKeypair() // wrong private key

	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	vcJSON := buildVC(t, "c", issuePub, wrongPriv) // signed with wrong key
	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != ladlerrors.ErrVCInvalidSignature {
		t.Errorf("got %v, want ErrVCInvalidSignature", err)
	}
}

func TestLevel3_MissingAgeClaim(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vc := map[string]interface{}{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   issuerDID,
		"issued":   "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id": "did:key:abc123",
			// no ageGroup field
		},
	}
	payload, _ := json.Marshal(vc)
	sig := ed25519.Sign(issuePriv, payload)
	vc["proof"] = map[string]interface{}{
		"type":               "Ed25519Signature2020",
		"verificationMethod": issuerDID,
		"jws":                base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vc)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != ladlerrors.ErrVCMissingAgeClaim {
		t.Errorf("got %v, want ErrVCMissingAgeClaim", err)
	}
}

func TestLevel3_MalformedJSON(t *testing.T) {
	_, priv, _ := identity.GenerateKeypair()
	ref := time.Now()
	_, err := verification.Level3([]byte("not json {{{"), "some-uuid", priv, &ref)
	if err == nil {
		t.Error("expected error for malformed VC JSON")
	}
}

func TestLevel3_UnsupportedDIDMethod(t *testing.T) {
	// Issuer using did:web instead of did:key — should fail.
	_, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	vc := map[string]interface{}{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential", "AgeCredential"},
		"issuer":   "did:web:example.com",
		"issued":   "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":       "did:key:abc",
			"ageGroup": "c",
		},
	}
	payload, _ := json.Marshal(vc)
	sig := ed25519.Sign(issuePriv, payload)
	vc["proof"] = map[string]interface{}{
		"type":               "Ed25519Signature2020",
		"verificationMethod": "did:web:example.com",
		"jws":                base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vc)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err == nil || !strings.Contains(err.Error(), "did:key") {
		t.Errorf("expected did:key error, got %v", err)
	}
}

func TestLevel3_SubjectSignatureInRecord(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	vcJSON := buildVC(t, "b", issuePub, issuePriv)
	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the record's subject sig is non-empty.
	if rec.UserSig == "" {
		t.Error("UserSig should not be empty")
	}
	// Verify UUID matches.
	if rec.UUID != uuid {
		t.Errorf("UUID = %q, want %q", rec.UUID, uuid)
	}
}
