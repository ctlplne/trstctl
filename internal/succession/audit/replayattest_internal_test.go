// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bytes"
	"math"
	"math/bits"
	"testing"
)

type writeIntCase struct {
	name string
	v    int
	want [8]byte
}

// TestWriteInt_BitIdenticalTwosComplement pins writeInt to hand-written literal
// bytes at the signedness boundaries. writeInt replaces a widening conversion in
// the event digest, so it must be a pure reinterpretation: the eight bytes are
// the value's two's-complement form sign-extended to 64 bits, big-endian, which
// is exactly what the previous encoding emitted. Any drift here silently re-keys
// every audit-chain head and projection checkpoint.
func TestWriteInt_BitIdenticalTwosComplement(t *testing.T) {
	cases := []writeIntCase{
		{"zero", 0, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"one", 1, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"two", 2, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}},
		{"minus_one", -1, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"minus_two", -2, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}},
		{"byte_boundary_255", 255, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}},
		{"byte_boundary_256", 256, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}},
		{"minus_256", -256, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}},
		{"max_int32", math.MaxInt32, [8]byte{0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF}},
		{"min_int32", math.MinInt32, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00}},
	}
	if bits.UintSize == 64 {
		// math.MaxInt/math.MinInt are untyped and fit an int on every platform, but
		// the literal byte forms below are the 64-bit ones.
		cases = append(cases,
			writeIntCase{"max_int", math.MaxInt, [8]byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
			writeIntCase{"min_int", math.MinInt, [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			writeIntCase{"staircase", 0x0102030405060708, [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeInt(&b, tc.v)
			if got := b.Bytes(); !bytes.Equal(got, tc.want[:]) {
				t.Fatalf("writeInt(%d) = % x, want % x", tc.v, got, tc.want)
			}
		})
	}
}

// TestWriteInt_MatchesWriteUintOnSharedRange keeps the two encoders aligned on
// the range they share: a non-negative schema version must digest identically
// whether it travels through writeInt or the pre-existing writeUint, so records
// written before and after the encoder change stay comparable.
func TestWriteInt_MatchesWriteUintOnSharedRange(t *testing.T) {
	// Each pair spells the same value in both types, so the comparison needs no
	// conversion to stand up.
	pairs := []struct {
		signed   int
		unsigned uint64
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{7, 7},
		{255, 255},
		{256, 256},
		{65535, 65535},
		{1 << 20, 1 << 20},
		{math.MaxInt32, math.MaxInt32},
	}
	for _, p := range pairs {
		var gotInt, gotUint bytes.Buffer
		writeInt(&gotInt, p.signed)
		writeUint(&gotUint, p.unsigned)
		if !bytes.Equal(gotInt.Bytes(), gotUint.Bytes()) {
			t.Fatalf("writeInt(%d) = % x, writeUint(%d) = % x", p.signed, gotInt.Bytes(), p.unsigned, gotUint.Bytes())
		}
	}
}
