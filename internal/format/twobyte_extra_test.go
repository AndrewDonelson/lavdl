package format_test

import (
"testing"

"github.com/AndrewDonelson/ladl/internal/format"
ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

// TestParseTwoBytes_NonDigitLevel covers the !unicode.IsDigit path in ParseTwoBytes.
func TestParseTwoBytes_NonDigitLevel(t *testing.T) {
_, err := format.ParseTwoBytes(format.TwoByteResponse("aX"))
if err != ladlerrors.ErrInvalidTwoByteResponse {
t.Errorf("ParseTwoBytes(aX) err = %v, want ErrInvalidTwoByteResponse", err)
}
}

// TestParseTwoBytes_LevelTooHigh covers the lvl > MaxLevel path in ParseTwoBytes.
func TestParseTwoBytes_LevelTooHigh(t *testing.T) {
_, err := format.ParseTwoBytes(format.TwoByteResponse("a8"))
if err != ladlerrors.ErrInvalidTwoByteResponse {
t.Errorf("ParseTwoBytes(a8) err = %v, want ErrInvalidTwoByteResponse", err)
}
}
