// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"bytes"
	"fmt"
	"math"
	"testing"
	"unicode"
)

// numconv_test.go holds the narrow numeric-conversion helpers the delegation tests
// share, plus the boundary tables that pin them. The generators in property_test.go,
// projection_test.go, and reachability_test.go all feed *_test.go-local counters and
// proptest.Rand.Intn results into unsigned domain fields. Those values are always
// non-negative, but "always" was an assumption spread across the call sites; these
// helpers make it a checked precondition in one place, so a generator that ever went
// negative fails the test loudly instead of wrapping into a huge budget/depth that
// silently changes what the property is asserting.

// nonNegU64 widens a non-negative test-generated count to uint64.
func nonNegU64(n int) uint64 {
	if n < 0 {
		panic(fmt.Sprintf("delegation test: nonNegU64 got negative value %d", n))
	}
	return uint64(n)
}

// nonNegU32 narrows a non-negative test-generated count to uint32.
func nonNegU32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic(fmt.Sprintf("delegation test: nonNegU32 got out-of-range value %d", n))
	}
	return uint32(n)
}

// asRune narrows a code point a test generator computed to a rune. The bound is
// unicode.MaxRune rather than MaxInt32: anything above it is not a code point at all,
// so string() would quietly substitute U+FFFD and collide distinct ids.
func asRune(n int) rune {
	if n < 0 || n > unicode.MaxRune {
		panic(fmt.Sprintf("delegation test: asRune got out-of-range code point %d", n))
	}
	return rune(n)
}

// TestNonNegConv_Boundaries pins the helpers against hand-written expected values at
// the ends of their accepted domains, and pins that they fail closed (panic) rather
// than wrap on a value outside it.
func TestNonNegConv_Boundaries(t *testing.T) {
	u64 := []struct {
		in   int
		want uint64
	}{
		{0, 0},
		{1, 1},
		{math.MaxInt32, 2147483647},
		{math.MaxInt64, 9223372036854775807},
	}
	for _, tc := range u64 {
		if got := nonNegU64(tc.in); got != tc.want {
			t.Fatalf("nonNegU64(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}

	u32 := []struct {
		in   int
		want uint32
	}{
		{0, 0},
		{1, 1},
		{math.MaxInt32, 2147483647},
		{math.MaxUint32, 4294967295},
	}
	for _, tc := range u32 {
		if got := nonNegU32(tc.in); got != tc.want {
			t.Fatalf("nonNegU32(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}

	assertPanics(t, "nonNegU64(-1)", func() { _ = nonNegU64(-1) })
	assertPanics(t, "nonNegU32(-1)", func() { _ = nonNegU32(-1) })
	assertPanics(t, "nonNegU32(MaxUint32+1)", func() { _ = nonNegU32(math.MaxUint32 + 1) })

	runes := []struct {
		in   int
		want rune
	}{
		{0, 0},
		{'a', 'a'},
		{'a' + 25, 'z'},
		{unicode.MaxRune, 1114111},
	}
	for _, tc := range runes {
		if got := asRune(tc.in); got != tc.want {
			t.Fatalf("asRune(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
	assertPanics(t, "asRune(-1)", func() { _ = asRune(-1) })
	assertPanics(t, "asRune(MaxRune+1)", func() { _ = asRune(unicode.MaxRune + 1) })
}

func assertPanics(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected panic, got none", name)
		}
	}()
	fn()
}

// TestWriteI64_TwosComplementBigEndian pins writeI64's output against hand-written
// literal byte strings at every interesting point of the int64 domain. writeI64 masks
// the bytes out of the signed value rather than reinterpreting it through uint64, so
// this table -- not a stdlib conversion -- is the oracle that the canonical encoding
// (and therefore every AGID authority digest) is byte-for-byte what it always was.
func TestWriteI64_TwosComplementBigEndian(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		want []byte
	}{
		{"zero", 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"one", 1, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"minus one", -1, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"minus two", -2, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}},
		{"max int64", math.MaxInt64, []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"min int64", math.MinInt64, []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"max int32", math.MaxInt32, []byte{0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF}},
		{"min int32", math.MinInt32, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00}},
		{"byte lanes", 0x0102030405060708, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"negative byte lanes", -0x0102030405060708, []byte{0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF8}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeI64(&b, tc.in)
			if got := b.Bytes(); !bytes.Equal(got, tc.want) {
				t.Fatalf("writeI64(%d) = % 02X, want % 02X", tc.in, got, tc.want)
			}
		})
	}
}
