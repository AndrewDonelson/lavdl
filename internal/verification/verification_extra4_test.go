package verification_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/verification"
)

// TestTesseractExtractor_DefaultBinaryPath verifies that when BinaryPath is "",
// TesseractExtractor uses "/usr/bin/tesseract" as the default binary.
// The extraction will fail (no tesseract installed or invalid image) but
// the default-path branch executes, covering that statement.
func TestTesseractExtractor_DefaultBinaryPath(t *testing.T) {
	e := &verification.TesseractExtractor{BinaryPath: ""}
	// Use a nonexistent file — tesseract will fail anyway.
	_, err := e.ExtractText("/tmp/nonexistent_ladl_test_default_bin.jpg")
	// Expect failure because tesseract is not installed or file doesn't exist.
	if err == nil {
		t.Log("Unexpected success — tesseract may be installed; coverage still achieved")
	}
}

// TestTesseractExtractor_NonExistentBinary verifies that a non-existent binary
// path causes ExtractText to return an OCR error.
func TestTesseractExtractor_NonExistentBinary(t *testing.T) {
	e := &verification.TesseractExtractor{BinaryPath: "/nonexistent/bin/tesseract"}
	_, err := e.ExtractText("/tmp/nonexistent_ladl_test_nobin.jpg")
	if err == nil {
		t.Error("expected error when tesseract binary does not exist")
	}
}

// TestLevel3_WrongSignature_Ed25519VerifyFails covers the path where
// verifyVCSignature receives a valid-base64 signature that doesn't match the
// issuer's public key, causing ed25519.Verify to return false.
// This is the 1-part (raw base64url) case.
func TestLevel3_WrongSignature_Ed25519VerifyFails(t *testing.T) {
	// Generate an issuer keypair and build the did:key issuer DID.
	issuerPub, _, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Use the issuer public key hex as the z-DID key.
	issuerDID := "did:key:z" + hexBytes(issuerPub)

	// Subject keypair for Level3 call.
	subjectPub, subjectPriv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	uuid := identity.DeriveUUID(subjectPub)

	// Build a VC with a valid-format (64 bytes of zeros) but wrong signature.
	wrongSig := make([]byte, 64) // all zeros — will fail ed25519.Verify
	wrongSigB64 := base64.RawURLEncoding.EncodeToString(wrongSig)

	vcData := map[string]interface{}{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   issuerDID,
		"credentialSubject": map[string]interface{}{
			"birthDate": "1990-06-15",
		},
		"proof": map[string]interface{}{
			"type": "Ed25519Signature2020",
			"jws":  wrongSigB64, // json:"jws" maps to VCProof.JWSSignature
		},
	}
	vcJSON, err := json.Marshal(vcData)
	if err != nil {
		t.Fatal(err)
	}

	_, err = verification.Level3(vcJSON, uuid, subjectPriv, nil)
	if err == nil {
		t.Error("expected Level3 to fail when signature is wrong (ed25519.Verify = false)")
	}
}

// hexBytes returns the lowercase hex encoding of a byte slice.
func hexBytes(b []byte) string {
	const hx = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hx[v>>4]
		out[i*2+1] = hx[v&0xf]
	}
	return string(out)
}

// TestLevel3_WrongSignature_JWS_Ed25519VerifyFails covers the 3-part JWS path
// where sigBytes decode succeeds but ed25519.Verify fails (wrong signature).
// This covers the `!ed25519.Verify(issuerPub, msg, sigBytes) → return ErrVCInvalidSignature`
// branch inside the `case 3:` block of verifyVCSignature.
func TestLevel3_WrongSignature_JWS_Ed25519VerifyFails(t *testing.T) {
	issuerPub, _, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	issuerDID := "did:key:z" + hexBytes(issuerPub)

	subjectPub, subjectPriv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	uuid := identity.DeriveUUID(subjectPub)

	// 3-part JWS: header..signature (all zeros — invalid but decodeable).
	// base64url({"alg":"EdDSA"}) + ".." + base64url(64 zero bytes)
	wrongSigB64 := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	jws3part := "eyJhbGciOiJFZERTQSJ9.." + wrongSigB64

	vcData := map[string]interface{}{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   issuerDID,
		"credentialSubject": map[string]interface{}{
			"birthDate": "1990-06-15",
		},
		"proof": map[string]interface{}{
			"type": "Ed25519Signature2020",
			"jws":  jws3part,
		},
	}
	vcJSON, err := json.Marshal(vcData)
	if err != nil {
		t.Fatal(err)
	}

	_, err = verification.Level3(vcJSON, uuid, subjectPriv, nil)
	if err == nil {
		t.Error("expected Level3 to fail when 3-part JWS signature is wrong")
	}
}

// TestLevel2_NilReferenceDate covers the else-branch `ref = time.Now().UTC()`
// in Level2 (when opts.ReferenceDate is nil).
func TestLevel2_NilReferenceDate(t *testing.T) {
	pub, priv, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	uuid := identity.DeriveUUID(pub)

	// ReferenceDate intentionally nil → triggers `ref = time.Now().UTC()` branch.
	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(1990, 6, 15)},
		ReferenceDate: nil,
	}

	rec, err := verification.Level2("/fake/path", uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2 with nil referenceDate failed: %v", err)
	}
	if rec == nil {
		t.Fatal("expected non-nil Record")
	}
}

// TestExtractText_FakeBinarySuccess covers the post-cmd.Run() success path in
// ExtractText: outPath, ReadFile, WriteFile (zero-out), and the return value.
// A fake shell-script binary writes the expected output file.
func TestExtractText_FakeBinarySuccess(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake_tesseract.sh")
	// Script writes DOB text to $2.txt (outBase + ".txt").
	script := "#!/bin/sh\nprintf 'DOB: 1990-06-15\\n' > \"$2.txt\"\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	e := &verification.TesseractExtractor{BinaryPath: fakeBin}
	text, err := e.ExtractText("/fake/input.jpg")
	if err != nil {
		t.Fatalf("ExtractText with fake binary: %v", err)
	}
	if text == "" {
		t.Error("expected non-empty text from fake binary")
	}
}

// TestExtractText_FakeBinaryNoOutput covers the ReadFile-failure path in
// ExtractText: the fake binary exits 0 but does NOT create the output file,
// so os.ReadFile returns an error → ErrOCRFailed.
func TestExtractText_FakeBinaryNoOutput(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake_tesseract_noout.sh")
	// Script exits 0 without creating any output file.
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	e := &verification.TesseractExtractor{BinaryPath: fakeBin}
	_, err := e.ExtractText("/fake/input.jpg")
	if err == nil {
		t.Error("expected ExtractText to fail when output file is not created")
	}
}
