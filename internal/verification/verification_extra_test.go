package verification_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/verification"
)

// =========================================================================
// Level3 edge cases
// =========================================================================

// buildVCJWS creates a W3C VC whose proof uses JWS 3-part compact serialisation.
// The signing input is base64url(header) + "." + base64url(vcWithoutProof).
func buildVCJWS(t *testing.T, ageGroup string, issuePub ed25519.PublicKey, issuePriv ed25519.PrivateKey) []byte {
	t.Helper()

	holder, _, _ := identity.GenerateKeypair()
	holderDID := "did:key:" + base64.RawURLEncoding.EncodeToString(holder)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential", "AgeCredential"},
		"issuer":   issuerDID,
		"issued":   "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":       holderDID,
			"ageGroup": ageGroup,
		},
	}

	// Marshal VC without proof — this matches what removeProofField returns.
	withoutProofBytes, err := json.Marshal(vcMap)
	if err != nil {
		t.Fatal(err)
	}

	// JWS header (base64url encoded).
	headerJSON := `{"alg":"EdDSA","typ":"JWT"}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))

	// Signing input = header + "." + base64url(withoutProof).
	payloadB64 := base64.RawURLEncoding.EncodeToString(withoutProofBytes)
	msg := []byte(headerB64 + "." + payloadB64)
	sig := ed25519.Sign(issuePriv, msg)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// JWS compact: header..sig (detached payload).
	jws := headerB64 + ".." + sigB64

	vcMap["proof"] = map[string]interface{}{
		"type":               "Ed25519Signature2020",
		"created":            "2024-01-01T00:00:00Z",
		"verificationMethod": issuerDID,
		"jws":                jws,
	}

	out, err := json.Marshal(vcMap)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLevel3_JWSCompactSignature(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	vcJSON := buildVCJWS(t, "d", issuePub, issuePriv)
	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() with JWS compact error = %v", err)
	}
	if rec.Payload.G != "d" {
		t.Errorf("group = %q, want %q", rec.Payload.G, "d")
	}
	if rec.Payload.L != 3 {
		t.Errorf("Payload.L = %d, want 3", rec.Payload.L)
	}
}

func TestLevel3_JWSCompactSignature_Invalid(t *testing.T) {
	issuePub, _, _ := identity.GenerateKeypair()
	_, wrongPriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	// Sign with wrong private key — JWS verification should fail.
	vcJSON := buildVCJWS(t, "d", issuePub, wrongPriv)
	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != ladlerrors.ErrVCInvalidSignature {
		t.Errorf("got %v, want ErrVCInvalidSignature (wrong key, JWS)", err)
	}
}

func TestLevel3_JWSInvalidPartsCount(t *testing.T) {
	// JWS with 2 parts (invalid) should return ErrVCInvalidSignature.
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   issuerDID,
		"issued":   "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":       "did:key:abc",
			"ageGroup": "d",
		},
	}
	payload, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, payload)
	// Deliberately invalid JWS: only 2 parts.
	vcMap["proof"] = map[string]interface{}{
		"type":               "Ed25519Signature2020",
		"verificationMethod": issuerDID,
		"jws":                "part1." + base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != ladlerrors.ErrVCInvalidSignature {
		t.Errorf("got %v, want ErrVCInvalidSignature (2 JWS parts)", err)
	}
}

func TestLevel3_ZPrefixHexDID(t *testing.T) {
	// Issuer DID uses z-prefix hex format.
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	// Build issuerDID with z-prefix hex encoding.
	issuerDID := "did:key:z" + hex.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential", "AgeCredential"},
		"issuer":   issuerDID,
		"issued":   "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":       "did:key:subject",
			"ageGroup": "c",
		},
	}

	withoutProofBytes, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, withoutProofBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	vcMap["proof"] = map[string]interface{}{
		"type":               "Ed25519Signature2020",
		"verificationMethod": issuerDID,
		"jws":                sigB64,
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() with z-prefix hex DID error = %v", err)
	}
	if rec.Payload.G != "c" {
		t.Errorf("group = %q, want %q", rec.Payload.G, "c")
	}
}

func TestLevel3_ZPrefixHexDID_InvalidLength(t *testing.T) {
	// z-prefix but with wrong hex length — should fail to resolve.
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	// "z" + 32 hex chars (16 bytes instead of 32) — too short.
	issuerDID := "did:key:z" + "aabbccddeeff00112233445566778899"
	_, issuePriv, _ := identity.GenerateKeypair()

	vcMap := map[string]interface{}{
		"issuer": issuerDID,
		"issued": "2024-01-01",
		"credentialSubject": map[string]interface{}{
			"ageGroup": "d",
		},
	}
	payload, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, payload)
	vcMap["proof"] = map[string]interface{}{
		"type": "Ed25519Signature2020",
		"jws":  base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err == nil {
		t.Error("Level3() with z-prefix invalid length DID should return error")
	}
}

func TestLevel3_BirthDateClaim(t *testing.T) {
	// VC credentialSubject contains "birthDate" instead of "ageGroup".
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   issuerDID,
		"issued":   "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":        "did:key:subject",
			"birthDate": "1990-06-15", // should compute to "d" at ref 2030-01-01
		},
	}
	withoutProof, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, withoutProof)
	vcMap["proof"] = map[string]interface{}{
		"type":               "Ed25519Signature2020",
		"verificationMethod": issuerDID,
		"jws":                base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() with birthDate error = %v", err)
	}
	if rec.Payload.G != "d" {
		t.Errorf("group = %q, want %q (born 1990, ref 2030 → age 39)", rec.Payload.G, "d")
	}
}

func TestLevel3_MinimumAgeClaim_21(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"issuer": issuerDID,
		"issued": "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"minimumAge": float64(21),
		},
	}
	withoutProof, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, withoutProof)
	vcMap["proof"] = map[string]interface{}{
		"type": "Ed25519Signature2020",
		"jws":  base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() minimumAge=21 error = %v", err)
	}
	if rec.Payload.G != "d" {
		t.Errorf("group = %q, want %q (minimumAge=21)", rec.Payload.G, "d")
	}
}

func TestLevel3_MinimumAgeClaim_18(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"issuer": issuerDID,
		"credentialSubject": map[string]interface{}{
			"minimumAge": float64(18),
		},
	}
	withoutProof, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, withoutProof)
	vcMap["proof"] = map[string]interface{}{
		"type": "Ed25519Signature2020",
		"jws":  base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() minimumAge=18 error = %v", err)
	}
	if rec.Payload.G != "c" {
		t.Errorf("group = %q, want %q (minimumAge=18)", rec.Payload.G, "c")
	}
}

func TestLevel3_MinimumAgeClaim_13(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"issuer": issuerDID,
		"credentialSubject": map[string]interface{}{
			"minimumAge": float64(13),
		},
	}
	withoutProof, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, withoutProof)
	vcMap["proof"] = map[string]interface{}{
		"type": "Ed25519Signature2020",
		"jws":  base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() minimumAge=13 error = %v", err)
	}
	if rec.Payload.G != "b" {
		t.Errorf("group = %q, want %q (minimumAge=13)", rec.Payload.G, "b")
	}
}

func TestLevel3_MinimumAgeClaim_Under13(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"issuer": issuerDID,
		"credentialSubject": map[string]interface{}{
			"minimumAge": float64(5),
		},
	}
	withoutProof, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, withoutProof)
	vcMap["proof"] = map[string]interface{}{
		"type": "Ed25519Signature2020",
		"jws":  base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() minimumAge=5 error = %v", err)
	}
	if rec.Payload.G != "a" {
		t.Errorf("group = %q, want %q (minimumAge=5)", rec.Payload.G, "a")
	}
}

func TestLevel3_AgeOver18AndNot21(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"issuer": issuerDID,
		"credentialSubject": map[string]interface{}{
			"ageOver18": true,
			"ageOver21": false,
		},
	}
	withoutProof, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, withoutProof)
	vcMap["proof"] = map[string]interface{}{
		"type": "Ed25519Signature2020",
		"jws":  base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() ageOver18=true,ageOver21=false error = %v", err)
	}
	if rec.Payload.G != "c" {
		t.Errorf("group = %q, want %q (ageOver18=true,ageOver21=false)", rec.Payload.G, "c")
	}
}

func TestLevel3_AgeOver18And21(t *testing.T) {
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"issuer": issuerDID,
		"credentialSubject": map[string]interface{}{
			"ageOver18": true,
			"ageOver21": true,
		},
	}
	withoutProof, _ := json.Marshal(vcMap)
	sig := ed25519.Sign(issuePriv, withoutProof)
	vcMap["proof"] = map[string]interface{}{
		"type": "Ed25519Signature2020",
		"jws":  base64.RawURLEncoding.EncodeToString(sig),
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != nil {
		t.Fatalf("Level3() ageOver18=true,ageOver21=true error = %v", err)
	}
	if rec.Payload.G != "d" {
		t.Errorf("group = %q, want %q (ageOver18=true,ageOver21=true)", rec.Payload.G, "d")
	}
}

func TestLevel3_MissingProofType(t *testing.T) {
	// A VC with empty proof type should return ErrVCInvalidSignature.
	issuePub, _, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)
	issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

	vcMap := map[string]interface{}{
		"issuer": issuerDID,
		"credentialSubject": map[string]interface{}{
			"ageGroup": "d",
		},
		"proof": map[string]interface{}{
			// type is empty — jws is also empty
		},
	}
	vcJSON, _ := json.Marshal(vcMap)

	ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
	if err != ladlerrors.ErrVCInvalidSignature {
		t.Errorf("got %v, want ErrVCInvalidSignature (missing proof type)", err)
	}
}

func TestLevel3_NilReferenceDate(t *testing.T) {
	// referenceDate=nil uses time.Now() — just ensure it doesn't panic.
	issuePub, issuePriv, _ := identity.GenerateKeypair()
	subjectPub, subjectPriv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(subjectPub)

	vcJSON := buildVC(t, "d", issuePub, issuePriv)

	rec, err := verification.Level3(vcJSON, uuid, subjectPriv, nil)
	if err != nil {
		t.Fatalf("Level3() with nil referenceDate error = %v", err)
	}
	if rec == nil {
		t.Error("Level3() with nil referenceDate returned nil record")
	}
}

// =========================================================================
// Level2 additional edge cases
// =========================================================================

func TestLevel2_USDateFormat(t *testing.T) {
	// DOB in US MM/DD/YYYY format.
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// "DOB: 01/15/1990" → parseDateString("01/15/1990") → "01-15-1990" → "01-02-2006"
	mrzText := "DOB: 01/15/1990\nSome other info"
	opts := &verification.L2Options{
		OCR:           &mockOCR{text: mrzText},
		ReferenceDate: refDate(2030, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2() US date format error = %v", err)
	}
	// Born 1990-01-15, ref 2030-01-01 → age 39 → group d.
	if rec.Payload.G != "d" {
		t.Errorf("US date: group = %q, want %q", rec.Payload.G, "d")
	}
}

func TestLevel2_GroupB_Teen(t *testing.T) {
	// Age 15 → group b.
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(2010, 6, 1)},
		ReferenceDate: refDate(2025, 6, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2() teen age error = %v", err)
	}
	if rec.Payload.G != "b" {
		t.Errorf("teen (age 15): group = %q, want %q", rec.Payload.G, "b")
	}
}

func TestLevel2_BareISODate_Fallback(t *testing.T) {
	// No DOB label — bare ISO date on a line triggers fallback pattern.
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: "random text\n1985-03-20\nmore text"},
		ReferenceDate: refDate(2025, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2() bare ISO date error = %v", err)
	}
	// Born 1985-03-20, ref 2025-01-01 → age 39 → group d.
	if rec.Payload.G != "d" {
		t.Errorf("bare ISO date: group = %q, want %q", rec.Payload.G, "d")
	}
}

func TestLevel2_MRZ6_InvalidLength(t *testing.T) {
	// parseMRZ6 with non-6-char input.
	// We can test this via extractDOB by providing a DOB label with a 5-digit value.
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// "DOB: 12345" — 5 digits, not a valid date.
	opts := &verification.L2Options{
		OCR: &mockOCR{text: "BIRTH: 12345\n"},
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	_, err := verification.Level2(tmpImg, uuid, priv, opts)
	// Should fail to find a valid DOB.
	if err != ladlerrors.ErrDOBNotFound {
		t.Errorf("got %v, want ErrDOBNotFound (5-digit YYMMDD)", err)
	}
}

func TestLevel2_MRZ6_Year1900s(t *testing.T) {
	// MRZ YYMMDD where yy > current year's last 2 digits → 1900s.
	// Use a year clearly in the 1900s: yy=50 → 1950.
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// MRZ line with DOB at positions 13-18: "500615"
	// Build a 44-char MRZ line: positions 13-18 = "500615"
	mrz := fmt.Sprintf("L898902C<3UTO%-6s1F9406236ZE184226B<<<<<14", "500615")
	if len(mrz) > 44 {
		mrz = mrz[:44]
	} else {
		for len(mrz) < 44 {
			mrz += "<"
		}
	}

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: mrz + "\n"},
		ReferenceDate: refDate(2025, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2() MRZ 1900s error = %v", err)
	}
	// Born 1950-06-15, ref 2025-01-01 → age 74 → group d.
	if rec.Payload.G != "d" {
		t.Errorf("MRZ 1950: group = %q, want %q", rec.Payload.G, "d")
	}
}

func TestLevel2_TesseractBinaryExistsButFails(t *testing.T) {
	// Use a real binary that exists (e.g. /bin/sh) but will fail when run as tesseract.
	// This tests the path: os.Stat succeeds, cmd.Run fails → ErrOCRFailed.
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// Create a fake "tesseract" that exits with an error.
	fakeScript := writeTempFile(t, []byte("#!/bin/sh\nexit 42\n"))
	os.Chmod(fakeScript, 0755)

	opts := &verification.L2Options{
		OCR: &verification.TesseractExtractor{BinaryPath: fakeScript},
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	_, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != ladlerrors.ErrOCRFailed {
		t.Errorf("got %v, want ErrOCRFailed (fake binary exits 42)", err)
	}
}

// =========================================================================
// signPayload edge cases
// =========================================================================

func TestSignPayload_NilPrivKey(t *testing.T) {
	// Level2 with a nil private key exercises the nil-key check in signPayload.
	// Level2 calls signPayload internally (Level1 uses ed25519.Sign directly).
	pub, _, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	validOCR := &mockOCR{text: dobText(1990, 6, 15)}
	ref := refDate(2030, 1, 1)
	opts := &verification.L2Options{
		OCR:           validOCR,
		ReferenceDate: ref,
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	_, err := verification.Level2(tmpImg, uuid, nil, opts)
	if err == nil {
		t.Error("Level2() with nil private key should return error")
	}
}
