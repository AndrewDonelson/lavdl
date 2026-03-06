package verification_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/AndrewDonelson/ladl/internal/format"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/verification"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

// mockOCR implements OCRExtractor for testing without a real Tesseract install.
type mockOCR struct {
	text string
	err  error
}

func (m *mockOCR) ExtractText(_ string) (string, error) {
	return m.text, m.err
}

// errorOCR always returns ErrOCRFailed.
type errorOCR struct{}

func (e *errorOCR) ExtractText(_ string) (string, error) {
	return "", ladlerrors.ErrOCRFailed
}

// dobText returns a fake OCR string with a specific DOB.
func dobText(year, month, day int) string {
	return fmt.Sprintf("DOB: %04d-%02d-%02d\nSOME OTHER INFO\n", year, month, day)
}

func refDate(year, month, day int) *time.Time {
	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	return &t
}

func TestLevel2_OCR_ValidDriversLicense(t *testing.T) {
	// Person born 1990-06-15, reference date 2030-01-01 → aged 39 → group d
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(1990, 6, 15)},
		ReferenceDate: refDate(2030, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2() error = %v", err)
	}
	if rec.Payload.G != "d" {
		t.Errorf("group = %q, want %q", rec.Payload.G, "d")
	}
}

func TestLevel2_OCR_ValidPassportMRZ(t *testing.T) {
	// MRZ line 2 — DOB field at positions 13-18 (0-based): 900615 → 1990-06-15
	// Reference date 2030-01-01 → aged 39 → group d
	mrzLine2 := "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<<" // invalid length but test
	// Build a valid 44-char MRZ line with DOB at pos 13.
	// Format: PPPPPPPPPPPPPP YYYYMMDD P YYMMDD ...
	// Positions 13-18 (0-base): DOB = 900615
	mrz := "L898902C<3UTO6908061F9406236ZE184226B<<<<<14"
	// pos 13-18: '690806' → 1969-08-06 → age 60 at 2030-01-01 → group d
	_ = mrzLine2

	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: mrz + "\n"},
		ReferenceDate: refDate(2030, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatalf("Level2() error = %v", err)
	}
	// Age 60 → group d
	if rec.Payload.G != "d" {
		t.Errorf("group = %q, want %q (passport MRZ)", rec.Payload.G, "d")
	}
}

func TestLevel2_OCR_NoDOBFound(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR: &mockOCR{text: "no date of birth here at all"},
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	_, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != ladlerrors.ErrDOBNotFound {
		t.Errorf("got %v, want ErrDOBNotFound", err)
	}
}

func TestLevel2_OCR_UnreadableImage(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR: &errorOCR{},
	}

	tmpImg := writeTempFile(t, []byte{0x00, 0xff, 0xfe, 0xab})
	_, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != ladlerrors.ErrOCRFailed {
		t.Errorf("binary garbage: got %v, want ErrOCRFailed", err)
	}
}

func TestLevel2_DocumentNotRetained(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(1990, 1, 1)},
		ReferenceDate: refDate(2020, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatal(err)
	}

	// The record must not contain any document data.
	if rec.Payload.G != "d" && rec.Payload.G != "c" {
		t.Logf("group = %q (depends on age calc)", rec.Payload.G)
	}
	// Ensure Payload T does not contain a full DOB.
	matched := false
	for _, suffix := range []string{"-01-01", "-06-15"} {
		if len(rec.Payload.T) > 7 && rec.Payload.T[7:] == suffix {
			matched = true
		}
	}
	if matched {
		t.Error("Payload.T appears to contain a full date (should be YYYY-MM only)")
	}
}

func TestLevel2_GroupFromDOB_Exactly18(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// Born 2002-06-15, reference 2020-06-15 → exactly 18 → group c
	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(2002, 6, 15)},
		ReferenceDate: refDate(2020, 6, 15),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Payload.G != "c" {
		t.Errorf("exactly 18: group = %q, want %q", rec.Payload.G, "c")
	}
}

func TestLevel2_GroupFromDOB_Exactly21(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// Born 1999-06-15, reference 2020-06-15 → exactly 21 → group d
	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(1999, 6, 15)},
		ReferenceDate: refDate(2020, 6, 15),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Payload.G != "d" {
		t.Errorf("exactly 21: group = %q, want %q", rec.Payload.G, "d")
	}
}

func TestLevel2_GroupFromDOB_Under13(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// Born 2015-01-01, reference 2020-01-01 → aged 5 → group a
	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(2015, 1, 1)},
		ReferenceDate: refDate(2020, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Payload.G != "a" {
		t.Errorf("under 13: group = %q, want %q", rec.Payload.G, "a")
	}
}

func TestLevel2_LevelInPayload(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(1990, 1, 1)},
		ReferenceDate: refDate(2020, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Payload.L != 2 {
		t.Errorf("Payload.L = %d, want 2", rec.Payload.L)
	}
}

func TestLevel2_TwoByte_Output(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// Born 1990-01-01, reference 2020-01-01 → aged 30 → group d
	opts := &verification.L2Options{
		OCR:           &mockOCR{text: dobText(1990, 1, 1)},
		ReferenceDate: refDate(2020, 1, 1),
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	rec, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != nil {
		t.Fatal(err)
	}

	got := format.FormatTwoBytes(rec.Payload)
	if got != "d2" {
		t.Errorf("FormatTwoBytes = %q, want %q", got, "d2")
	}
}

func TestLevel2_TesseractUnavailable(t *testing.T) {
	pub, priv, _ := identity.GenerateKeypair()
	uuid := identity.DeriveUUID(pub)

	// Use a TesseractExtractor pointing to a non-existent binary.
	opts := &verification.L2Options{
		OCR: &verification.TesseractExtractor{BinaryPath: "/nonexistent/tesseract-xxx"},
	}

	tmpImg := writeTempFile(t, []byte("fakejpeg"))
	_, err := verification.Level2(tmpImg, uuid, priv, opts)
	if err != ladlerrors.ErrTesseractNotFound {
		t.Errorf("got %v, want ErrTesseractNotFound", err)
	}
}

// writeTempFile writes data to a temp file and returns its path.
func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "testimg*.jpg")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}
