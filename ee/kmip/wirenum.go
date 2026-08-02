// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"fmt"
	"math"
)

// Numeric conversions at the KMIP wire boundary.
//
// KMIP encodes Integer and Enumeration as SIGNED 32-bit big-endian, and Go's
// encoding/binary only offers unsigned readers, so every decode has to
// reinterpret the bits. Doing that inline as int32(binary.BigEndian.Uint32(b))
// is correct but indistinguishable, at a glance, from an accidental narrowing
// that silently corrupts a value — and the corpus had both kinds mixed together.
//
// These helpers separate the two intentions permanently:
//
//   - wireInt32 / putInt32 / putInt64 REINTERPRET. Every input maps to exactly
//     one output, nothing is lost, and there is no error to return.
//   - frameLen32 NARROWS, so it is fallible and returns an error. Every caller
//     must decide what to do when a length does not fit, which is the point:
//     these lengths come off the network.
//
// None of them needs a #nosec. The reinterpreting helpers are written so the
// range is provable at each conversion, and the narrowing one is range-checked.

// wireInt32 reinterprets the four bytes of a KMIP Integer or Enumeration as the
// signed value they encode. It is exactly int32(u) — the branch exists so the
// range is provable at each conversion rather than asserted in a comment.
func wireInt32(u uint32) int32 {
	if u <= math.MaxInt32 {
		return int32(u)
	}
	return -int32(math.MaxUint32-u) - 1
}

// putInt32 writes v into buf[:4] as big-endian two's complement, the KMIP
// Integer/Enumeration encoding. It masks each byte out of the signed value
// directly, so no signed-to-unsigned conversion happens at all. The result is
// byte-identical to binary.BigEndian.PutUint32(buf, uint32(v)) across the whole
// int32 domain, including math.MinInt32 (see TestWireNumRoundTrip).
func putInt32(buf []byte, v int32) {
	_ = buf[3] // bounds check once
	buf[0] = byte(v >> 24 & 0xFF)
	buf[1] = byte(v >> 16 & 0xFF)
	buf[2] = byte(v >> 8 & 0xFF)
	buf[3] = byte(v & 0xFF)
}

// putInt64 writes v into buf[:8] as big-endian two's complement, the KMIP
// DateTime encoding (POSIX seconds, signed — dates before 1970 are legal).
func putInt64(buf []byte, v int64) {
	_ = buf[7] // bounds check once
	for i := 0; i < 8; i++ {
		buf[i] = byte(v >> (56 - 8*i) & 0xFF)
	}
}

// frameLen32 narrows a Go length to the uint32 a KMIP TTLV length field holds.
//
// Unlike the helpers above this one can fail, and it must: a value longer than
// 4 GiB has no valid encoding, and silently truncating it would emit a frame
// whose declared length disagrees with its payload — which a peer parses as the
// next item, i.e. it desynchronises the stream.
func frameLen32(n int) (uint32, error) {
	if n < 0 || int64(n) > math.MaxUint32 {
		return 0, fmt.Errorf("kmip: length %d does not fit a TTLV length field", n)
	}
	return uint32(n), nil
}

// wireInt32From narrows a Go int to the int32 a KMIP Integer holds, refusing
// anything outside the range rather than wrapping it into a different number.
func wireInt32From(n int) (int32, error) {
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0, fmt.Errorf("kmip: value %d does not fit a KMIP Integer", n)
	}
	return int32(n), nil
}
