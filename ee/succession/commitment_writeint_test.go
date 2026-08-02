// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"bytes"
	"math"
	"testing"
)

// TestWriteInt_TwosComplementBytes pins writeInt to the exact 8-byte
// two's-complement big-endian encoding it replaced. The expected bytes are
// hand-written literals, not derived from a Go conversion, so this test is an
// independent oracle: these encodings are covered by succession signatures and a
// single flipped byte silently invalidates every previously issued artifact.
func TestWriteInt_TwosComplementBytes(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		want [8]byte
	}{
		{"zero", 0, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"one", 1, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"minus_one", -1, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"minus_two", -2, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}},
		{"max_int64", math.MaxInt64, [8]byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"min_int64", math.MinInt64, [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"max_int32", math.MaxInt32, [8]byte{0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF}},
		{"min_int32", math.MinInt32, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00}},
		// Every byte lane distinct, so a transposed or dropped lane is caught.
		{"lane_ladder", 0x0102030405060708, [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"lane_ladder_negative", -0x0102030405060708, [8]byte{0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF8}},
		// A realistic Unix-second timestamp (2026-08-06T00:00:00Z = 1785974400).
		{"unix_seconds", 1785974400, [8]byte{0x00, 0x00, 0x00, 0x00, 0x6A, 0x73, 0xCE, 0x80}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeInt(&b, tc.in)
			if got := b.Bytes(); !bytes.Equal(got, tc.want[:]) {
				t.Fatalf("writeInt(%d) = % X, want % X", tc.in, got, tc.want)
			}
		})
	}
}

// TestWriteInt_MatchesWriteUintOnNonNegatives proves writeInt agrees with the
// existing unsigned encoder over the non-negative range, where the two encodings
// are required to be identical. This does not use a signed->unsigned conversion
// as the oracle: the uint64 inputs are written as literals.
func TestWriteInt_MatchesWriteUintOnNonNegatives(t *testing.T) {
	cases := []struct {
		signed   int64
		unsigned uint64
	}{
		{0, 0},
		{1, 1},
		{255, 255},
		{256, 256},
		{math.MaxInt32, 0x7FFFFFFF},
		{math.MaxInt64, 0x7FFFFFFFFFFFFFFF},
		{1785974400, 1785974400},
	}
	for _, tc := range cases {
		var gotInt, gotUint bytes.Buffer
		writeInt(&gotInt, tc.signed)
		writeUint(&gotUint, tc.unsigned)
		if !bytes.Equal(gotInt.Bytes(), gotUint.Bytes()) {
			t.Fatalf("writeInt(%d) = % X, writeUint(%d) = % X", tc.signed, gotInt.Bytes(), tc.unsigned, gotUint.Bytes())
		}
	}
}
