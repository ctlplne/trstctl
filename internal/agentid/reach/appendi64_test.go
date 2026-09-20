// SPDX-License-Identifier: BUSL-1.1

package reach

import (
	"bytes"
	"testing"
)

// appendi64_test.go pins the canonical signed-integer writer to HAND-WRITTEN expected
// byte strings. appendI64 is a bit-level reinterpretation: it must emit exactly the 8
// fixed big-endian bytes of the value's two's-complement pattern, which is what the
// reachable-set and verdict canonical encodings (and therefore every signature over
// them) have always committed to. The expected values below are written out literally
// rather than computed from a conversion, so this test is an independent oracle for the
// encoding rather than a restatement of it.
func TestAppendI64CanonicalBytes(t *testing.T) {
	t.Parallel()

	const (
		maxInt64 = int64(9223372036854775807)  // 0x7FFFFFFFFFFFFFFF
		minInt64 = int64(-9223372036854775808) // 0x8000000000000000
	)

	cases := []struct {
		name string
		in   int64
		want []byte
	}{
		{
			name: "zero",
			in:   0,
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "one",
			in:   1,
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
		{
			name: "negative_one",
			in:   -1,
			want: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name: "negative_two",
			in:   -2,
			want: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE},
		},
		{
			name: "max_int64",
			in:   maxInt64,
			want: []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name: "min_int64",
			in:   minInt64,
			want: []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "max_uint32_as_positive",
			in:   4294967295, // 0x00000000FFFFFFFF
			want: []byte{0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name: "min_int32",
			in:   -2147483648, // sign-extends to 0xFFFFFFFF80000000
			want: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00},
		},
		{
			name: "every_byte_distinct",
			in:   0x0102030405060708,
			want: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			name: "unix_second",
			in:   1785974400,
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x6A, 0x73, 0xCE, 0x80},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := appendI64(nil, tc.in)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("appendI64(nil, %d) = % X, want % X", tc.in, got, tc.want)
			}
		})
	}
}

// TestAppendI64AppendsInPlace checks appendI64 appends to (rather than replaces) the
// caller's buffer, since the canonical encoders thread one growing slice through every
// field and a writer that dropped the prefix would silently change every digest.
func TestAppendI64AppendsInPlace(t *testing.T) {
	t.Parallel()

	prefix := []byte{0xAA, 0xBB}
	got := appendI64(prefix, -1)
	want := []byte{0xAA, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if !bytes.Equal(got, want) {
		t.Fatalf("appendI64 with prefix = % X, want % X", got, want)
	}
}

// TestAppendI64MatchesAppendU64ForNonNegative locks the two writers together on the
// non-negative range, where the previous appendU64(b, uint64(v)) spelling and the new
// appendI64(b, v) spelling must agree byte for byte. This is the wire-compatibility half
// of the guarantee: verdicts signed before the change still verify after it.
func TestAppendI64MatchesAppendU64ForNonNegative(t *testing.T) {
	t.Parallel()

	for _, v := range []int64{0, 1, 2, 255, 256, 65535, 1785974400, 4294967295, 9223372036854775807} {
		signed := appendI64(nil, v)
		// The uint64 side is built from a literal-safe non-negative value, so no
		// conversion of an unknown-sign quantity is involved.
		var u uint64
		for _, b := range signed {
			u = u<<8 | uint64(b)
		}
		unsigned := appendU64(nil, u)
		if !bytes.Equal(signed, unsigned) {
			t.Fatalf("appendI64(%d) = % X, appendU64 = % X", v, signed, unsigned)
		}
	}
}
