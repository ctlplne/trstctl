// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke

import "testing"

// aggregate_internal_test.go pins the byte-level encoding appendU64 produces. The
// aggregate artifact's CompletionEvidenceDigest is a digest over these bytes and is
// verified OFFLINE by third parties (AGID-claim-18), so the encoding is a wire format:
// any drift silently invalidates every previously minted artifact. The expected values
// below are hand-written big-endian literals, not recomputed from the implementation,
// so the test is an independent oracle rather than a tautology.
func TestAppendU64_BigEndianEncoding(t *testing.T) {
	cases := []struct {
		name string
		v    uint64
		want [8]byte
	}{
		{"zero", 0, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"one", 1, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"max_uint64", 18446744073709551615, [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"max_int64", 9223372036854775807, [8]byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"min_int64_bit_pattern", 9223372036854775808, [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"max_uint32", 4294967295, [8]byte{0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"distinct_octets", 0x0102030405060708, [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"high_bit_per_octet", 0x8040201008040201, [8]byte{0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appendU64(nil, tc.v)
			if len(got) != 8 {
				t.Fatalf("appendU64(nil, %d) length = %d, want 8", tc.v, len(got))
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("appendU64(nil, %d) = % x, want % x", tc.v, got, tc.want[:])
				}
			}
			// It APPENDS: an existing prefix is preserved and the 8 bytes follow it.
			withPrefix := appendU64([]byte{0xAA, 0xBB}, tc.v)
			if len(withPrefix) != 10 || withPrefix[0] != 0xAA || withPrefix[1] != 0xBB {
				t.Fatalf("appendU64(prefix, %d) = % x, want prefix aa bb preserved", tc.v, withPrefix)
			}
			for i := range tc.want {
				if withPrefix[2+i] != tc.want[i] {
					t.Fatalf("appendU64(prefix, %d) tail = % x, want % x", tc.v, withPrefix[2:], tc.want[:])
				}
			}
		})
	}
}
