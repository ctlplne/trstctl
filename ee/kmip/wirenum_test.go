// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"encoding/binary"
	"math"
	"testing"
)

// TestWireNumIsExactlyTheStdlibConversion is the safety argument for wirenum.go.
//
// These helpers exist so no #nosec is needed at the KMIP wire boundary, which is
// only legitimate if they are BIT-IDENTICAL to the conversions they replace. A
// helper that is merely "probably right" would be worse than the inline
// conversion it replaced, because it hides the narrowing behind a friendly name.
//
// The boundary values are the ones that actually break: MinInt32 (whose negation
// overflows), MaxInt32/MaxInt32+1 (the sign flip), and -1 (all bits set).
func TestWireNumIsExactlyTheStdlibConversion(t *testing.T) {
	for _, u := range []uint32{
		0, 1, 2, math.MaxInt32 - 1, math.MaxInt32, math.MaxInt32 + 1,
		math.MaxUint32 - 1, math.MaxUint32, 0xDEADBEEF, 0x80000000,
	} {
		if got, want := wireInt32(u), int32(u); got != want { //nolint:gosec // the oracle IS the conversion under test
			t.Errorf("wireInt32(%#x) = %d, want %d", u, got, want)
		}
	}
	for _, v := range []int32{
		0, 1, -1, 2, -2, math.MaxInt32, math.MinInt32, math.MinInt32 + 1, -12345, 0x7EADBEE,
	} {
		var got, want [4]byte
		putInt32(got[:], v)
		binary.BigEndian.PutUint32(want[:], uint32(v)) //nolint:gosec // the oracle IS the conversion under test
		if got != want {
			t.Errorf("putInt32(%d) = % x, want % x", v, got, want)
		}
		if rt := wireInt32(binary.BigEndian.Uint32(got[:])); rt != v {
			t.Errorf("round trip %d -> % x -> %d", v, got, rt)
		}
	}
	for _, v := range []int64{0, 1, -1, math.MaxInt64, math.MinInt64, 1767225600, -2208988800} {
		var got, want [8]byte
		putInt64(got[:], v)
		binary.BigEndian.PutUint64(want[:], uint64(v)) //nolint:gosec // the oracle IS the conversion under test
		if got != want {
			t.Errorf("putInt64(%d) = % x, want % x", v, got, want)
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
