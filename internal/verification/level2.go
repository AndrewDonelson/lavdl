// level2.go — Document-Assisted OCR verification (Level 2).
package verification

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/format"
)

// OCRExtractor abstracts document OCR for testing.
type OCRExtractor interface {
	// ExtractText runs OCR on the image at imagePath and returns raw text.
	ExtractText(imagePath string) (string, error)
}

// TesseractExtractor runs the system tesseract binary.
type TesseractExtractor struct {
	BinaryPath string
	Lang       string
}

// ExtractText invokes tesseract on imagePath and returns the plain text output.
// The document image itself is never written by LADL — it is provided by the user.
func (te *TesseractExtractor) ExtractText(imagePath string) (string, error) {
	// Verify tesseract exists.
	bin := te.BinaryPath
	if bin == "" {
		bin = "/usr/bin/tesseract"
	}
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		// Also try PATH.
		var pathErr error
		bin, pathErr = exec.LookPath("tesseract")
		if pathErr != nil {
			return "", ladlerrors.ErrTesseractNotFound
		}
	}

	lang := te.Lang
	if lang == "" {
		lang = "eng"
	}

	// Write OCR output to a temp file, then read and zero it.
	tmpDir, err := os.MkdirTemp("", "ladl-ocr-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	outBase := filepath.Join(tmpDir, "out")

	cmd := exec.Command(bin, imagePath, outBase, "-l", lang, "--psm", "3")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", ladlerrors.ErrOCRFailed
	}

	outPath := outBase + ".txt"
	raw, err := os.ReadFile(outPath)
	if err != nil {
		return "", ladlerrors.ErrOCRFailed
	}

	// Zero the file contents before returning.
	_ = os.WriteFile(outPath, make([]byte, len(raw)), 0600)

	return string(raw), nil
}

// L2Options are optional overrides for the Level 2 flow (primarily for testing).
type L2Options struct {
	// OCR overrides the default TesseractExtractor.
	OCR OCRExtractor
	// ReferenceDate overrides time.Now() for age calculation (used in tests).
	ReferenceDate *time.Time
}

// Level2 performs a document-assisted OCR verification.
//
// It runs OCR on the document at documentPath, extracts the date of birth,
// computes the age group, and returns a signed Record with level 2.
// The document content is never retained.
func Level2(documentPath, uuid string, priv ed25519.PrivateKey, opts *L2Options) (*Record, error) {
	var ocr OCRExtractor = &TesseractExtractor{}
	if opts != nil && opts.OCR != nil {
		ocr = opts.OCR
	}

	text, err := ocr.ExtractText(documentPath)
	if err != nil {
		return nil, err
	}

	dob, err := extractDOB(text)
	if err != nil {
		return nil, err
	}

	var ref time.Time
	if opts != nil && opts.ReferenceDate != nil {
		ref = *opts.ReferenceDate
	} else {
		ref = time.Now().UTC()
	}

	group := ageGroupFromDOB(dob, ref)

	now := ref
	t := now.Format("2006-01")

	payload := format.VerificationPayload{
		G: group,
		L: 2,
		T: t,
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

// dobPatterns are regex patterns for extracting date of birth from OCR text.
// They cover US driver's licenses, passport MRZ, and generic ISO date formats.
var dobPatterns = []*regexp.Regexp{
	// ISO: YYYY-MM-DD or YYYY/MM/DD
	regexp.MustCompile(`(?i)(?:DOB|Date of Birth|Birth Date|Born)[:\s]+(\d{4}[-/]\d{2}[-/]\d{2})`),
	// US style: MM/DD/YYYY
	regexp.MustCompile(`(?i)(?:DOB|Date of Birth|Birth Date|Born)[:\s]+(\d{1,2}/\d{1,2}/\d{4})`),
	// MRZ style: YYMMDD (passport line 2, positions 14-19)
	regexp.MustCompile(`(?i)(?:DOB|BIRTH)[:\s]+(\d{6})`),
	// Bare ISO date anywhere on line
	regexp.MustCompile(`\b(\d{4}[-/]\d{2}[-/]\d{2})\b`),
}

// mrzLinePattern matches ICAO TD3 MRZ line 2 (44 chars starting with digit).
var mrzLinePattern = regexp.MustCompile(`[A-Z0-9<]{44}`)

// extractDOB tries all patterns and MRZ parsing to find a date of birth.
func extractDOB(text string) (time.Time, error) {
	// Try labelled patterns first.
	for _, re := range dobPatterns[:3] {
		m := re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		t, err := parseDateString(m[1])
		if err == nil {
			return t, nil
		}
	}

	// Try MRZ parsing (passport line 2).
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if mrzLinePattern.MatchString(line) && len(line) >= 44 {
			// MRZ TD3 line 2: DOB at positions 13–18 (0-indexed)
			dobStr := line[13:19]
			if t, err := parseMRZ6(dobStr); err == nil {
				return t, nil
			}
		}
	}

	// Try bare ISO as last resort.
	m := dobPatterns[3].FindStringSubmatch(text)
	if m != nil {
		if t, err := parseDateString(m[1]); err == nil {
			return t, nil
		}
	}

	return time.Time{}, ladlerrors.ErrDOBNotFound
}

// parseDateString handles YYYY-MM-DD, YYYY/MM/DD, MM/DD/YYYY and YYMMDD.
func parseDateString(s string) (time.Time, error) {
	s = strings.ReplaceAll(s, "/", "-")

	layouts := []string{
		"2006-01-02",
		"01-02-2006",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}

	// YYMMDD (6 digits)
	if len(s) == 6 {
		return parseMRZ6(s)
	}

	return time.Time{}, fmt.Errorf("unrecognised date: %s", s)
}

// parseMRZ6 decodes a 6-digit YYMMDD date, assuming years >= 00 mean 2000-2099
// and years > current year's two-digit are in the 1900s.
func parseMRZ6(s string) (time.Time, error) {
	if len(s) != 6 {
		return time.Time{}, fmt.Errorf("invalid MRZ date length")
	}
	yy, err := strconv.Atoi(s[0:2])
	if err != nil {
		return time.Time{}, err
	}
	mm, err := strconv.Atoi(s[2:4])
	if err != nil {
		return time.Time{}, err
	}
	dd, err := strconv.Atoi(s[4:6])
	if err != nil {
		return time.Time{}, err
	}

	// Pivot: if yy <= current year's last two digits, assume 2000s, else 1900s.
	currentYY := time.Now().Year() % 100
	var year int
	if yy <= currentYY {
		year = 2000 + yy
	} else {
		year = 1900 + yy
	}

	t := time.Date(year, time.Month(mm), dd, 0, 0, 0, 0, time.UTC)
	if t.IsZero() {
		return time.Time{}, fmt.Errorf("invalid MRZ date")
	}
	return t, nil
}

// ageGroupFromDOB maps a date of birth to an age group letter.
//
//	a: 0–12
//	b: 13–17
//	c: 18–20
//	d: 21+
func ageGroupFromDOB(dob, ref time.Time) string {
	age := ageAt(dob, ref)
	switch {
	case age < 13:
		return "a"
	case age < 18:
		return "b"
	case age < 21:
		return "c"
	default:
		return "d"
	}
}

// ageAt computes the completed years between dob and ref.
func ageAt(dob, ref time.Time) int {
	years := ref.Year() - dob.Year()
	// Subtract one if the birthday hasn't occurred yet this year.
	bday := time.Date(ref.Year(), dob.Month(), dob.Day(), 0, 0, 0, 0, time.UTC)
	if ref.Before(bday) {
		years--
	}
	return years
}
