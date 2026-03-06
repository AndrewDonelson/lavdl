package format_test

import (
"testing"

"github.com/AndrewDonelson/ladl/internal/format"

ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
)

func TestFormatTwoBytes_D2(t *testing.T) {
p := format.VerificationPayload{G: "d", L: 2}
got := format.FormatTwoBytes(p)
if got != "d2" {
t.Errorf("FormatTwoBytes({d,2}) = %q, want %q", got, "d2")
}
}

func TestFormatTwoBytes_A0(t *testing.T) {
p := format.VerificationPayload{G: "a", L: 0}
got := format.FormatTwoBytes(p)
if got != "a0" {
t.Errorf("FormatTwoBytes({a,0}) = %q, want %q", got, "a0")
}
}

func TestFormatTwoBytes_EmptyGroup(t *testing.T) {
p := format.VerificationPayload{G: "", L: 0}
got := format.FormatTwoBytes(p)
if got != "-0" {
t.Errorf("FormatTwoBytes({empty,0}) = %q, want %q", got, "-0")
}
}

func TestFormatTwoBytes_AlwaysLowercase(t *testing.T) {
for _, g := range []string{"a", "b", "c", "d", "-"} {
p := format.VerificationPayload{G: g, L: 1}
got := string(format.FormatTwoBytes(p))
if len(got) > 0 && got[0] >= 'A' && got[0] <= 'Z' {
t.Errorf("FormatTwoBytes produced uppercase group: %q", got)
}
}
}

func TestFormatTwoBytes_Length(t *testing.T) {
cases := []format.VerificationPayload{
{G: "d", L: 2},
{G: "a", L: 0},
{G: "b", L: 1},
{G: "", L: 0},
}
for _, p := range cases {
got := format.FormatTwoBytes(p)
if len(got) != 2 {
t.Errorf("FormatTwoBytes(%+v) length = %d, want 2", p, len(got))
}
}
}

func TestParseTwoBytes_Valid(t *testing.T) {
p, err := format.ParseTwoBytes("d2")
if err != nil {
t.Fatalf("ParseTwoBytes(d2) error = %v", err)
}
if p.G != "d" || p.L != 2 {
t.Errorf("ParseTwoBytes(d2) = %+v, want {G:d, L:2}", p)
}
}

func TestParseTwoBytes_Unverified(t *testing.T) {
p, err := format.ParseTwoBytes("-0")
if err != nil {
t.Fatalf("ParseTwoBytes(-0) error = %v", err)
}
if p.G != "-" || p.L != 0 {
t.Errorf("ParseTwoBytes(-0) = %+v, want {G:-, L:0}", p)
}
}

func TestParseTwoBytes_Invalid(t *testing.T) {
_, err := format.ParseTwoBytes("X9")
if err != ladlerrors.ErrInvalidTwoByteResponse {
t.Errorf("ParseTwoBytes(X9) error = %v, want ErrInvalidTwoByteResponse", err)
}
}

func TestParseTwoBytes_WrongLength(t *testing.T) {
for _, s := range []string{"d", "d21", "", "abc"} {
_, err := format.ParseTwoBytes(format.TwoByteResponse(s))
if err != ladlerrors.ErrInvalidTwoByteResponse {
t.Errorf("ParseTwoBytes(%q) error = %v, want ErrInvalidTwoByteResponse", s, err)
}
}
}

func TestParseTwoBytes_AllValidGroups(t *testing.T) {
for _, g := range []string{"a", "b", "c", "d", "-"} {
s := g + "1"
p, err := format.ParseTwoBytes(format.TwoByteResponse(s))
if err != nil {
t.Errorf("ParseTwoBytes(%q) unexpected error: %v", s, err)
continue
}
if p.G != g {
t.Errorf("ParseTwoBytes(%q).G = %q, want %q", s, p.G, g)
}
}
}
