// Package format implements the two-byte response encoding used by LADL.
//
// The canonical response format is exactly two bytes: {group}{level}
// where group is one of '-' 'a' 'b' 'c' 'd' and level is a digit 0-3.
// Examples: "d2", "c1", "-0"
package format

import (
	"fmt"
	"strings"
	"unicode"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

// ValidGroups lists all valid age group characters in order.
const ValidGroups = "-abcd"

// MaxLevel is the maximum numeric verification level.
const MaxLevel = 3

// TwoByteResponse is the canonical response returned by GET /q/{uuid}.
type TwoByteResponse string

// String satisfies the fmt.Stringer interface.
func (t TwoByteResponse) String() string { return string(t) }

// VerificationPayload is stored as the Payload of the Strata L4Record.
// Field names are deliberately terse — this is the only data on the public ledger.
type VerificationPayload struct {
	G string `json:"g"` // age group: "-" | "a" | "b" | "c" | "d"
	L int    `json:"l"` // verification level: 0 | 1 | 2 | 3
	T string `json:"t"` // coarse timestamp: "YYYY-MM"
}

// FormatTwoBytes produces the canonical two-byte string from a payload.
// Returns "-0" for an empty group. Always lowercase.
func FormatTwoBytes(p VerificationPayload) TwoByteResponse {
	g := p.G
	if g == "" {
		g = "-"
	}
	return TwoByteResponse(fmt.Sprintf("%s%d", strings.ToLower(g), p.L))
}

// ParseTwoBytes decodes a TwoByteResponse string into a VerificationPayload.
// Returns ErrInvalidTwoByteResponse if the string is not valid.
func ParseTwoBytes(s TwoByteResponse) (VerificationPayload, error) {
	raw := string(s)
	if len(raw) != 2 {
		return VerificationPayload{}, ladlerrors.ErrInvalidTwoByteResponse
	}
	g := string(raw[0])
	if !strings.Contains(ValidGroups, g) {
		return VerificationPayload{}, ladlerrors.ErrInvalidTwoByteResponse
	}
	lvlRune := rune(raw[1])
	if !unicode.IsDigit(lvlRune) {
		return VerificationPayload{}, ladlerrors.ErrInvalidTwoByteResponse
	}
	lvl := int(lvlRune - '0')
	if lvl > MaxLevel {
		return VerificationPayload{}, ladlerrors.ErrInvalidTwoByteResponse
	}
	return VerificationPayload{G: g, L: lvl}, nil
}

// ValidateGroup returns ErrInvalidAgeGroup if g is not one of a, b, c, d (lowercase).
func ValidateGroup(g string) error {
	if g == "" || !strings.Contains("abcd", strings.ToLower(g)) || len(g) != 1 {
		return ladlerrors.ErrInvalidAgeGroup
	}
	if g != strings.ToLower(g) {
		return ladlerrors.ErrInvalidAgeGroup
	}
	return nil
}
