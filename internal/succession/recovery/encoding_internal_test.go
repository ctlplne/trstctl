// SPDX-License-Identifier: BUSL-1.1

package recovery

import (
	"bytes"
	"math"
	"strconv"
	"testing"
)

// TestWriteInt_TwosComplementBigEndian pins writeInt to the 64-bit
// two's-complement big-endian encoding, byte for byte. The expected values are
// written out by hand rather than derived from a uint64(v) conversion: this
// encoding feeds the trust-root roster signature, so it must be pinned against
// something independent of the conversion writeInt replaced.
func TestWriteInt_TwosComplementBigEndian(t *testing.T) {
	type tc struct {
		name string
		in   int
		want [8]byte
	}
	cases := []tc{
		{"zero", 0, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"one", 1, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"two", 2, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}},
		{"minus one", -1, [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"minus two", -2, [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}},
		{"255", 255, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff}},
		{"256", 256, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}},
		{"minus 256", -256, [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}},
		{"MaxInt32", math.MaxInt32, [8]byte{0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff}},
		{"MinInt32", math.MinInt32, [8]byte{0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00}},
	}
	// math.MaxInt / math.MinInt are platform-width, so their encodings are too.
	if strconv.IntSize == 64 {
		cases = append(cases,
			tc{"MaxInt (64-bit)", math.MaxInt, [8]byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
			tc{"MinInt (64-bit)", math.MinInt, [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		)
	} else {
		cases = append(cases,
			tc{"MaxInt (32-bit)", math.MaxInt, [8]byte{0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff}},
			tc{"MinInt (32-bit)", math.MinInt, [8]byte{0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00}},
		)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			writeInt(&b, c.in)
			if got := b.Bytes(); !bytes.Equal(got, c.want[:]) {
				t.Fatalf("writeInt(%d) = % x, want % x", c.in, got, c.want[:])
			}
		})
	}
}

// TestWriteInt_AgreesWithWriteUintOnNonNegative: on non-negative values — every
// threshold the roster encoding can legitimately carry — writeInt must emit the
// same bytes as the unsigned writer used for the roster's other fields, so
// roster signatures produced before this helper existed still verify. The
// unsigned side is fed a uint64 literal directly (not a conversion of v), so the
// two encoders stay genuinely independent.
func TestWriteInt_AgreesWithWriteUintOnNonNegative(t *testing.T) {
	pairs := []struct {
		signed   int
		unsigned uint64
	}{
		{0, 0}, {1, 1}, {2, 2}, {3, 3}, {255, 255}, {256, 256},
		{65535, 65535}, {1 << 20, 1 << 20}, {math.MaxInt32, math.MaxInt32},
	}
	for _, p := range pairs {
		var gotInt, gotUint bytes.Buffer
		writeInt(&gotInt, p.signed)
		writeUint(&gotUint, p.unsigned)
		if !bytes.Equal(gotInt.Bytes(), gotUint.Bytes()) {
			t.Fatalf("writeInt(%d) = % x, writeUint(%d) = % x",
				p.signed, gotInt.Bytes(), p.unsigned, gotUint.Bytes())
		}
	}
}

// TestEncodeRoster_ThresholdPlacement: the threshold occupies the eight bytes
// immediately after the domain-separator field, encoded exactly as writeInt
// emits it. This pins the wiring, not just the helper.
func TestEncodeRoster_ThresholdPlacement(t *testing.T) {
	const threshold = 2
	enc := encodeRoster(threshold, []Approver{{ID: "a1", PubDER: []byte{0x01}}})

	off := 8 + len(rosterDomain) // length prefix + domain bytes
	if len(enc) < off+8 {
		t.Fatalf("encodeRoster too short: %d bytes", len(enc))
	}
	want := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	if got := enc[off : off+8]; !bytes.Equal(got, want) {
		t.Fatalf("threshold bytes = % x, want % x", got, want)
	}

	// A different threshold must produce a different roster preimage, so a roster
	// signature cannot be replayed across thresholds.
	if bytes.Equal(enc, encodeRoster(3, []Approver{{ID: "a1", PubDER: []byte{0x01}}})) {
		t.Fatal("encodeRoster is insensitive to the threshold")
	}
}
