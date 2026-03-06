package verification_test

import (
"crypto/ed25519"
"encoding/base64"
"encoding/json"
"testing"
"time"

ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
"github.com/AndrewDonelson/ladl/internal/identity"
"github.com/AndrewDonelson/ladl/internal/verification"
)

// TestParseDateString_UnrecognisedFormat exercises the final error return
// in parseDateString via an OCR text with a bare ISO-looking date that is invalid.
func TestParseDateString_UnrecognisedDateViaBareISO(t *testing.T) {
// A bare ISO pattern "9999-99-99" is matched by dobPatterns[3] but
// parseDateString fails (invalid month 99) → falls through to ErrDOBNotFound.
pub, priv, _ := identity.GenerateKeypair()
uuid := identity.DeriveUUID(pub)

opts := &verification.L2Options{
OCR: &mockOCR{text: "ID: 9999-99-99\n"},
}
tmpImg := writeTempFile(t, []byte("fakejpeg"))
_, err := verification.Level2(tmpImg, uuid, priv, opts)
if err != ladlerrors.ErrDOBNotFound {
t.Errorf("got %v, want ErrDOBNotFound (unrecognised bare date)", err)
}
}

// TestParseDateString_LabelledYYMMDD exercises the 6-digit YYMMDD label path.
// "DOB: 900615" → parseDateString("900615") → len==6 → parseMRZ6 → 1990-06-15.
func TestParseDateString_LabelledYYMMDD(t *testing.T) {
pub, priv, _ := identity.GenerateKeypair()
uuid := identity.DeriveUUID(pub)

opts := &verification.L2Options{
OCR:           &mockOCR{text: "DOB: 900615\n"},
ReferenceDate: refDate(2030, 1, 1),
}
tmpImg := writeTempFile(t, []byte("fakejpeg"))
rec, err := verification.Level2(tmpImg, uuid, priv, opts)
if err != nil {
t.Fatalf("Level2() labelled YYMMDD error = %v", err)
}
// Born 1990-06-15, ref 2030-01-01 → age 39 → group d
if rec.Payload.G != "d" {
t.Errorf("group = %q, want %q (DOB: 900615)", rec.Payload.G, "d")
}
}

// TestLevel3_BirthDateClaim_NilRefDate tests the else-branch of the nil
// referenceDate check inside extractAgeClaimFromVC with a birthDate claim.
func TestLevel3_BirthDateClaim_NilRefDate(t *testing.T) {
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
"birthDate": "1990-06-15",
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

// Passing nil referenceDate — exercises the else branch (uses time.Now()).
rec, err := verification.Level3(vcJSON, uuid, subjectPriv, nil)
if err != nil {
t.Fatalf("Level3() birthDate nil refDate error = %v", err)
}
// Born 1990 — should be group d (30+) with current time reference.
if rec == nil {
t.Error("Level3() returned nil record")
}
}

// TestLevel3_InvalidSignatureBase64Decode covers the base64 decode error path
// in verifyVCSignature for the 1-part case.
func TestLevel3_InvalidSignatureBase64Decode(t *testing.T) {
issuePub, _ , _ := identity.GenerateKeypair()
subjectPub, subjectPriv, _ := identity.GenerateKeypair()
uuid := identity.DeriveUUID(subjectPub)
issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

vcMap := map[string]interface{}{
"issuer": issuerDID,
"credentialSubject": map[string]interface{}{
"ageGroup": "d",
},
}
vcMap["proof"] = map[string]interface{}{
"type": "Ed25519Signature2020",
"jws":  "not-valid-base64!!!",
}
vcJSON, _ := json.Marshal(vcMap)

ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
if err != ladlerrors.ErrVCInvalidSignature {
t.Errorf("got %v, want ErrVCInvalidSignature (invalid base64)", err)
}
}

// TestLevel3_JWSInvalidSigBase64Decode covers base64 decode error in the JWS 3-part path.
func TestLevel3_JWSInvalidSigBase64Decode(t *testing.T) {
issuePub, _, _ := identity.GenerateKeypair()
subjectPub, subjectPriv, _ := identity.GenerateKeypair()
uuid := identity.DeriveUUID(subjectPub)
issuerDID := "did:key:" + base64.RawURLEncoding.EncodeToString(issuePub)

vcMap := map[string]interface{}{
"issuer": issuerDID,
"credentialSubject": map[string]interface{}{
"ageGroup": "d",
},
}
// 3-part JWS with invalid base64 in the signature part.
vcMap["proof"] = map[string]interface{}{
"type": "Ed25519Signature2020",
"jws":  "header..not-valid-base64!!!",
}
vcJSON, _ := json.Marshal(vcMap)

ref := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
_, err := verification.Level3(vcJSON, uuid, subjectPriv, &ref)
if err != ladlerrors.ErrVCInvalidSignature {
t.Errorf("got %v, want ErrVCInvalidSignature (invalid JWS sig base64)", err)
}
}
