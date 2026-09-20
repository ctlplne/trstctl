// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
)

// int64WireVectors pins the 8-byte big-endian two's-complement encoding of the signed
// commitment-timestamp fields to hand-written literal bytes, at the boundaries. These
// expectations are written out by hand rather than derived from a conversion, so they
// are an independent oracle for putI64/fieldReader.i64 — the pair must stay
// bit-identical to the reinterpreting encoding the wire format was defined with.
var int64WireVectors = []struct {
	name string
	v    int64
	enc  [8]byte
}{
	{"zero", 0, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	{"one", 1, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
	{"minus one", -1, [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	{"minus two", -2, [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}},
	{"max int64", math.MaxInt64, [8]byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	{"min int64", math.MinInt64, [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	{"max uint32", 4294967295, [8]byte{0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}},
	{"min int32", -2147483648, [8]byte{0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00}},
	{"every byte distinct", 0x0102030405060708, [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
	{"unix seconds", 1754166272, [8]byte{0x00, 0x00, 0x00, 0x00, 0x68, 0x8e, 0x74, 0x00}},
}

func TestPutI64MatchesLiteralWireBytes(t *testing.T) {
	for _, tc := range int64WireVectors {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			putI64(&b, tc.v)
			if got := b.Bytes(); !bytes.Equal(got, tc.enc[:]) {
				t.Fatalf("putI64(%d) = % x, want % x", tc.v, got, tc.enc[:])
			}
		})
	}
}

func TestFieldReaderI64MatchesLiteralWireBytes(t *testing.T) {
	for _, tc := range int64WireVectors {
		t.Run(tc.name, func(t *testing.T) {
			// Trailing sentinel byte proves i64 consumes exactly 8 bytes.
			r := &fieldReader{b: append(append([]byte{}, tc.enc[:]...), 0xAB)}
			got, ok := r.i64()
			if !ok {
				t.Fatalf("i64(% x) not ok", tc.enc[:])
			}
			if got != tc.v {
				t.Fatalf("i64(% x) = %d, want %d", tc.enc[:], got, tc.v)
			}
			if len(r.b) != 1 || r.b[0] != 0xAB {
				t.Fatalf("i64 did not consume exactly 8 bytes, remainder = % x", r.b)
			}
		})
	}
}

func TestFieldReaderI64ShortBuffer(t *testing.T) {
	for n := 0; n < 8; n++ {
		r := &fieldReader{b: make([]byte, n)}
		if v, ok := r.i64(); ok || v != 0 {
			t.Fatalf("i64 with %d bytes = (%d, %v), want (0, false)", n, v, ok)
		}
	}
}

// TestMarshalFieldsSignedTimestampsRoundTrip walks the signed timestamp fields through
// the full wire encoding at the int64 boundaries, which the ordinary round-trip test
// (using plausible unix seconds) does not reach.
func TestMarshalFieldsSignedTimestampsRoundTrip(t *testing.T) {
	for _, tc := range int64WireVectors {
		t.Run(tc.name, func(t *testing.T) {
			f := succession.CommitmentFields{
				DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/app", TenantID: "t",
				PredecessorAlg: crypto.ECDSAP256, SuccessorAlg: crypto.ECDSAP384,
				NotBefore: tc.v, NotAfter: tc.v,
			}
			got, err := UnmarshalFields(MarshalFields(f))
			if err != nil {
				t.Fatalf("UnmarshalFields: %v", err)
			}
			if got.NotBefore != tc.v || got.NotAfter != tc.v {
				t.Fatalf("round trip = (%d, %d), want (%d, %d)", got.NotBefore, got.NotAfter, tc.v, tc.v)
			}
		})
	}
}

// TestUnmarshalFieldsRejectsOversizedCommitmentVersion proves the decoder fails closed
// on a commitment version wider than the uint32 field can hold, rather than silently
// truncating it to a different version — which would let a peer steer the agent onto
// the wrong commitment domain.
func TestUnmarshalFieldsRejectsOversizedCommitmentVersion(t *testing.T) {
	base := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/app", TenantID: "t",
		PredecessorAlg: crypto.ECDSAP256, SuccessorAlg: crypto.ECDSAP384,
		NotBefore: 10, NotAfter: 20,
	}
	// Locate the CommitmentVersion field by flipping only that field and diffing.
	zero := MarshalFields(base)
	bumped := base
	bumped.CommitmentVersion = 1
	one := MarshalFields(bumped)
	if len(zero) != len(one) {
		t.Fatalf("encodings differ in length: %d vs %d", len(zero), len(one))
	}
	last := -1
	for i := range zero {
		if zero[i] != one[i] {
			if last != -1 {
				t.Fatalf("more than one byte differs (%d and %d)", last, i)
			}
			last = i
		}
	}
	if last < 7 {
		t.Fatalf("CommitmentVersion byte not found (last = %d)", last)
	}

	for _, cv := range []uint64{math.MaxUint32 + 1, math.MaxUint64} {
		enc := append([]byte{}, zero...)
		binary.BigEndian.PutUint64(enc[last-7:last+1], cv)
		if _, err := UnmarshalFields(enc); err == nil {
			t.Fatalf("CommitmentVersion %d accepted, want ErrFieldsMalformed", cv)
		}
	}
	// The in-range boundary still decodes exactly.
	enc := append([]byte{}, zero...)
	binary.BigEndian.PutUint64(enc[last-7:last+1], math.MaxUint32)
	got, err := UnmarshalFields(enc)
	if err != nil {
		t.Fatalf("CommitmentVersion MaxUint32: %v", err)
	}
	if got.CommitmentVersion != math.MaxUint32 {
		t.Fatalf("CommitmentVersion = %d, want %d", got.CommitmentVersion, uint32(math.MaxUint32))
	}
}
