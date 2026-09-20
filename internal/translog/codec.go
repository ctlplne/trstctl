// SPDX-License-Identifier: BUSL-1.1

package translog

// codec.go holds the two's-complement primitives shared by the STH and Proof wire
// encodings. Both encodings are byte-exact commitments that signatures are computed
// over, so these routines must stay bit-identical to a plain big-endian
// uint64/int64 reinterpretation: changing a single byte changes every signature the
// log has ever produced. codec_test.go pins them against hand-written literals at
// the boundaries.

// putI64BE writes v's two's-complement big-endian encoding into dst.
//
// Each byte is masked out of v directly rather than reinterpreting the whole scalar
// as uint64 first. Arithmetic right shift sign-extends, but the & 0xFF keeps only
// the eight bits of the selected byte, so the result is identical to
// binary.BigEndian.PutUint64(dst[:], uint64(v)) for every int64 including negatives.
func putI64BE(dst *[8]byte, v int64) {
	dst[0] = byte(v >> 56 & 0xFF)
	dst[1] = byte(v >> 48 & 0xFF)
	dst[2] = byte(v >> 40 & 0xFF)
	dst[3] = byte(v >> 32 & 0xFF)
	dst[4] = byte(v >> 24 & 0xFF)
	dst[5] = byte(v >> 16 & 0xFF)
	dst[6] = byte(v >> 8 & 0xFF)
	dst[7] = byte(v & 0xFF)
}

// i64BE reinterprets an eight-byte big-endian wire word as the two's-complement
// int64 it encodes. The value is accumulated straight into an int64 — Go defines
// signed shift overflow as two's-complement wrapping — so the assembled scalar is
// never routed through uint64 and never converted. It is total (every one of the
// 2^64 words maps to exactly one int64) and is the exact inverse of putI64BE.
func i64BE(src [8]byte) int64 {
	var v int64
	for _, b := range src {
		v = v<<8 | int64(b)
	}
	return v
}
