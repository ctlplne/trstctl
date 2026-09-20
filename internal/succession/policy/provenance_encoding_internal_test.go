// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"bytes"
	"testing"
)

// TestWriteInt_TwosComplementBytes pins writeInt to the frozen 8-byte big-endian
// two's-complement encoding of an int64. Expected values are hand-written literals,
// not derived from a conversion, so this test is an independent oracle for the
// signed-message encoding at the range boundaries.
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
		{"minus_256", -256, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}},
		{"max_int64", 9223372036854775807, [8]byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"min_int64", -9223372036854775808, [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"max_int32", 2147483647, [8]byte{0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF}},
		{"min_int32", -2147483648, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00}},
		{"unix_timestamp", 1700000000, [8]byte{0x00, 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00}},
		{"pre_epoch_timestamp", -1700000000, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x9A, 0xAC, 0x0F, 0x00}},
		{"every_byte_distinct", 0x0102030405060708, [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
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

// TestWriteInt_MatchesFrozenUnsignedEncoding checks that writeInt agrees with the
// pre-existing writeUint framing on the non-negative range that both accept, so the
// signed-artifact messages did not change shape. The unsigned side is written with
// hand-literal bit patterns rather than a conversion of the signed input.
func TestWriteInt_MatchesFrozenUnsignedEncoding(t *testing.T) {
	cases := []struct {
		signed   int64
		unsigned uint64
	}{
		{0, 0x0000000000000000},
		{1, 0x0000000000000001},
		{255, 0x00000000000000FF},
		{1700000000, 0x000000006553F100},
		{9223372036854775807, 0x7FFFFFFFFFFFFFFF},
	}
	for _, tc := range cases {
		var si, ui bytes.Buffer
		writeInt(&si, tc.signed)
		writeUint(&ui, tc.unsigned)
		if !bytes.Equal(si.Bytes(), ui.Bytes()) {
			t.Fatalf("writeInt(%d) = % X, writeUint(%#016x) = % X", tc.signed, si.Bytes(), tc.unsigned, ui.Bytes())
		}
	}
}

// TestMessages_FrozenGoldenBytes pins the three signed-message encodings to golden
// byte strings so any future change to the field framing (including the timestamp
// encoding) breaks loudly instead of silently invalidating recorded signatures.
func TestMessages_FrozenGoldenBytes(t *testing.T) {
	t.Run("finding_negative_timestamp", func(t *testing.T) {
		got := findingMessage(Finding{ObservedAt: -1})
		// Six length-prefixed fields (domain, then five empty strings), then the
		// timestamp as all-ones two's complement.
		want := append(lengthPrefixed(findingDomain),
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // finding_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // identity_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tenant_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // algorithm ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reason ""
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // observed_at -1
		)
		if !bytes.Equal(got, want) {
			t.Fatalf("findingMessage = % X, want % X", got, want)
		}
	})

	t.Run("plan_min_int64_timestamp", func(t *testing.T) {
		got := planMessage(Plan{CreatedAt: -9223372036854775808})
		want := append(lengthPrefixed(planDomain),
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // plan_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // identity_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tenant_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // finding_digest nil
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target_algorithm ""
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // created_at MinInt64
		)
		if !bytes.Equal(got, want) {
			t.Fatalf("planMessage = % X, want % X", got, want)
		}
	})

	t.Run("decision_allow_and_max_timestamp", func(t *testing.T) {
		got := decisionMessage(Decision{Allow: true, DecidedAt: 9223372036854775807})
		want := append(lengthPrefixed(decisionDomain),
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // decision_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // identity_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tenant_id ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // plan_digest nil
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target_algorithm ""
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // allow = 1
			0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // decided_at MaxInt64
		)
		if !bytes.Equal(got, want) {
			t.Fatalf("decisionMessage = % X, want % X", got, want)
		}
	})
}

// lengthPrefixed builds the 8-byte-big-endian-length + payload framing for a domain
// separator, using only the string's own length so the helper adds no new assumptions.
func lengthPrefixed(s string) []byte {
	n := int64(len(s))
	out := []byte{
		byte(n >> 56 & 0xFF),
		byte(n >> 48 & 0xFF),
		byte(n >> 40 & 0xFF),
		byte(n >> 32 & 0xFF),
		byte(n >> 24 & 0xFF),
		byte(n >> 16 & 0xFF),
		byte(n >> 8 & 0xFF),
		byte(n & 0xFF),
	}
	return append(out, s...)
}
