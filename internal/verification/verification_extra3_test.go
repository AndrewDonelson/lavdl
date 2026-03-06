package verification_test

import (
	"testing"

	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/verification"
)

// TestParseMRZ6_Year2000s covers the yy <= currentYY → year = 2000+yy path.
// "DOB: 000615" → parseDateString("000615") → parseMRZ6("000615") → yy=0 → 2000-06-15.
func TestParseMRZ6_Year2000s_Label(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// DOB prefix label triggers dobPatterns[2] which captures exactly 6 digits.
	opts := &verification.L2Options{
		OCR:           &mockOCR{text: "DOB: 000615\n"},
		ReferenceDate: refDate(2024, 1, 1),
	}
	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2() YYMMDD year 2000s error = %v", err)
	}
	// Born 2000-06-15, ref 2024-01-01 → age 23 → group d (age >= 21)
	if rec.Payload.G != "d" {
		t.Errorf("MRZ 2000s: group = %q, want %q", rec.Payload.G, "d")
	}
}

// TestParseMRZ6_SmallCurrentYY ensures the 2000s branch with yy=10.
// "DOB: 101201" → year 2010, ref 2030 → age 19 → group c.
func TestParseMRZ6_Year2000s_Age19(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: "DOB: 101201\n"},
		ReferenceDate: refDate(2030, 6, 1),
	}
	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2() YYMMDD 2010 error = %v", err)
	}
	// Born 2010-12-01, ref 2030-06-01 → age 19 → group c
	if rec.Payload.G != "c" {
		t.Errorf("MRZ 2010: group = %q, want %q", rec.Payload.G, "c")
	}
}

// TestParseMRZ6_Via_MRZLine_AtioError covers the Atoi error path in parseMRZ6
// when extractDOB receives a 44-char MRZ TD3 line where the DOB field at
// positions 13-18 contains non-digit characters (e.g. "<").
//
// The MRZ line: ABCDEFGHIJKLM + 9<0615 + padding to 44 chars.
// parseMRZ6("9<0615") → strconv.Atoi("9<") → error → extractDOB skips.
// No labelled-DOB fallback, so Level2 returns ErrDOBNotFound.
func TestParseMRZ6_Via_MRZLine_AtioError(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// Positions 13-18 = "9<0615" trigger first-Atoi failure in parseMRZ6.
	mrz := "ABCDEFGHIJKLM9<0615"
	for len(mrz) < 44 {
		mrz += "A"
	}
	// No labelled DOB — extractDOB must try the MRZ path and fail.
	opts := &verification.L2Options{
		OCR:           &mockOCR{text: mrz},
		ReferenceDate: refDate(2024, 1, 1),
	}
	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	_, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err == nil {
		t.Error("expected Level2 to fail when MRZ DOB field contains non-digit chars")
	}
}

// TestParseMRZ6_Via_MRZLine_SecondAtioError covers second strconv.Atoi failure.
// positions 13-18 = "909<15" → Atoi("90")=ok, Atoi("9<")=error at second call.
func TestParseMRZ6_Via_MRZLine_SecondAtioError(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	mrz := "ABCDEFGHIJKLM909<15"
	for len(mrz) < 44 {
		mrz += "A"
	}

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: mrz},
		ReferenceDate: refDate(2024, 1, 1),
	}
	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	_, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err == nil {
		t.Error("expected Level2 to fail when MRZ month field has non-digit char")
	}
}

// TestParseMRZ6_Via_MRZLine_ThirdAtioError covers third strconv.Atoi failure.
// positions 13-18 = "90069<" → Atoi("90")=ok, Atoi("06")=ok, Atoi("9<")=error.
func TestParseMRZ6_Via_MRZLine_ThirdAtioError(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	mrz := "ABCDEFGHIJKLM90069<"
	for len(mrz) < 44 {
		mrz += "A"
	}

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: mrz},
		ReferenceDate: refDate(2024, 1, 1),
	}
	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	_, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err == nil {
		t.Error("expected Level2 to fail when MRZ day field has non-digit char")
	}
}
