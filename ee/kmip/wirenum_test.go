// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"encoding/binary"
	"math"
	"testing"
)

// TestWireNumMatchesKnownEncodings is the safety argument for wirenum.go.
//
// These helpers exist so no #nosec is needed at the KMIP wire boundary, which is
// only legitimate if they are BIT-IDENTICAL to the conversions they replace. A
// helper that is merely "probably right" would be worse than the inline
// conversion it replaced, because it hides the narrowing behind a friendly name.
//
// The expected values are written out as literals rather than computed from the
// stdlib conversion. That is deliberate twice over: the repository forbids
// nolint escape hatches, so the oracle cannot be int32(u) itself; and a
// hand-checked table cannot drift along with the implementation the way a
// computed oracle can.
//
// The cases are the ones that actually break: MinInt32 (whose negation
// overflows), MaxInt32 and MaxInt32+1 (the sign flip), -1 (all bits set), and
// MaxUint32.
func TestWireNumMatchesKnownEncodings(t *testing.T) {
	for _, tc := range []struct {
		in   uint32
		want int32
	}{
		{0x00000000, 0},
		{0x00000001, 1},
		{0x00000002, 2},
		{0x7FFFFFFE, 2147483646},
		{0x7FFFFFFF, 2147483647},
		{0x80000000, -2147483648},
		{0xFFFFFFFE, -2},
		{0xFFFFFFFF, -1},
		{0xDEADBEEF, -559038737},
		{0x80000000, -2147483648},
	} {
		if got := wireInt32(tc.in); got != tc.want {
			t.Errorf("wireInt32(%#08x) = %d, want %d", tc.in, got, tc.want)
		}
	}

	for _, tc := range []struct {
		in   int32
		want [4]byte
	}{
		{0, [4]byte{0x00, 0x00, 0x00, 0x00}},
		{1, [4]byte{0x00, 0x00, 0x00, 0x01}},
		{-1, [4]byte{0xff, 0xff, 0xff, 0xff}},
		{2, [4]byte{0x00, 0x00, 0x00, 0x02}},
		{-2, [4]byte{0xff, 0xff, 0xff, 0xfe}},
		{2147483647, [4]byte{0x7f, 0xff, 0xff, 0xff}},
		{-2147483648, [4]byte{0x80, 0x00, 0x00, 0x00}},
		{-12345, [4]byte{0xff, 0xff, 0xcf, 0xc7}},
		{132832238, [4]byte{0x07, 0xea, 0xdb, 0xee}},
	} {
		var got [4]byte
		putInt32(got[:], tc.in)
		if got != tc.want {
			t.Errorf("putInt32(%d) = % x, want % x", tc.in, got, tc.want)
		}
		if rt := wireInt32(binary.BigEndian.Uint32(got[:])); rt != tc.in {
			t.Errorf("round trip %d -> % x -> %d", tc.in, got, rt)
		}
	}

	for _, tc := range []struct {
		in   int64
		want [8]byte
	}{
		{0, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{1, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{-1, [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{9223372036854775807, [8]byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{-9223372036854775808, [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{1767225600, [8]byte{0x00, 0x00, 0x00, 0x00, 0x69, 0x55, 0xb9, 0x00}},
		{-2208988800, [8]byte{0xff, 0xff, 0xff, 0xff, 0x7c, 0x55, 0x81, 0x80}},
	} {
		var got [8]byte
		putInt64(got[:], tc.in)
		if got != tc.want {
			t.Errorf("putInt64(%d) = % x, want % x", tc.in, got, tc.want)
		}
	}
}

// TestFrameLenAndIntegerNarrowingRefuseOutOfRange proves the fallible helpers
// actually fail, rather than being range checks that can never fire.
func TestFrameLenAndIntegerNarrowingRefuseOutOfRange(t *testing.T) {
	if _, err := frameLen32(-1); err == nil {
		t.Error("frameLen32(-1) must fail: a negative length has no encoding")
	}
	if got, err := frameLen32(math.MaxUint32); err != nil || got != math.MaxUint32 {
		t.Errorf("frameLen32(MaxUint32) = %d, %v; want the value and no error", got, err)
	}
	if _, err := wireInt32From(math.MaxInt32 + 1); err == nil {
		t.Error("wireInt32From(MaxInt32+1) must fail rather than wrap to a negative number")
	}
	if _, err := wireInt32From(math.MinInt32 - 1); err == nil {
		t.Error("wireInt32From(MinInt32-1) must fail")
	}
	if got, err := wireInt32From(math.MinInt32); err != nil || got != math.MinInt32 {
		t.Errorf("wireInt32From(MinInt32) = %d, %v; want the value and no error", got, err)
	}
}
