// SPDX-License-Identifier: LicenseRef-trstctl-EE

package store_test

import (
	"context"
	"math"
	"reflect"
	"testing"

	"trstctl.com/trstctl/ee/proptest"

	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
)

// seqDig makes a distinct 32-byte digest for an integer so chain nodes have unique
// ids in the property test. The leading 8 bytes are i+1 big-endian, written by
// masking each byte out of the value rather than converting the scalar to uint64
// (the bytes are identical either way; see TestSeqDig_BigEndianBytes).
func seqDig(i int) []byte {
	b := make([]byte, 32)
	v := i + 1
	b[0] = byte(v >> 56 & 0xFF)
	b[1] = byte(v >> 48 & 0xFF)
	b[2] = byte(v >> 40 & 0xFF)
	b[3] = byte(v >> 32 & 0xFF)
	b[4] = byte(v >> 24 & 0xFF)
	b[5] = byte(v >> 16 & 0xFF)
	b[6] = byte(v >> 8 & 0xFF)
	b[7] = byte(v & 0xFF)
	return b
}

// TestSeqDig_BigEndianBytes pins seqDig's leading 8 bytes against hand-written
// literals at the boundaries, so the mask-based byte extraction is verified to be
// bit-identical to a big-endian uint64 encoding of i+1 without using a conversion
// as its own oracle.
func TestSeqDig_BigEndianBytes(t *testing.T) {
	cases := []struct {
		in   int
		want [8]byte
	}{
		{in: -1, want: [8]byte{0, 0, 0, 0, 0, 0, 0, 0}},                                        // -1+1 = 0
		{in: 0, want: [8]byte{0, 0, 0, 0, 0, 0, 0, 1}},                                         // 0+1 = 1
		{in: 1, want: [8]byte{0, 0, 0, 0, 0, 0, 0, 2}},                                         // 1+1 = 2
		{in: 254, want: [8]byte{0, 0, 0, 0, 0, 0, 0, 0xFF}},                                    // 255
		{in: 255, want: [8]byte{0, 0, 0, 0, 0, 0, 0x01, 0x00}},                                 // 256
		{in: 0xFFFFFFFE, want: [8]byte{0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF}},                    // 2^32-1
		{in: 0xFFFFFFFF, want: [8]byte{0, 0, 0, 0x01, 0x00, 0x00, 0x00, 0x00}},                 // 2^32
		{in: -2, want: [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},                // -1 two's complement
		{in: math.MaxInt64 - 1, want: [8]byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}, // MaxInt64
		{in: math.MinInt64, want: [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},     // MinInt64+1
	}
	for _, tc := range cases {
		got := seqDig(tc.in)
		if len(got) != 32 {
			t.Fatalf("seqDig(%d): len %d, want 32", tc.in, len(got))
		}
		if !reflect.DeepEqual(got[:8], tc.want[:]) {
			t.Errorf("seqDig(%d) head = %v, want %v", tc.in, got[:8], tc.want)
		}
		for i := 8; i < 32; i++ {
			if got[i] != 0 {
				t.Errorf("seqDig(%d): tail byte %d = %d, want 0", tc.in, i, got[i])
			}
		}
	}
}

// TestChainFetch_OrderedAndGaplessProperty is the property that FetchChain returns a
// linear chain ordered root-to-leaf and gapless for many random-length chains
// inserted in random order (acceptance criterion 4 / test-first "chain fetch is
// ordered and gapless"). Each chain is a single spine root -> ... -> leaf; the
// credential is issued over the leaf. The returned chain must be exactly the
// generated records in root-to-leaf order.
func TestChainFetch_OrderedAndGaplessProperty(t *testing.T) {
	repo := newRepoOn(t, "agid_chainprop")
	ctx := context.Background()

	for seed := 0; seed < 25; seed++ {
		rng := proptest.New(int64(seed))
		length := 1 + rng.Intn(6) // 1..6 records

		base := seed * 100
		var records []agidstore.DelegationRecord
		var wantOrder [][]byte
		// seq counts the ledger sequence as a uint64 from the start, so the
		// record/issuance sequences never round-trip through a signed int.
		var seq uint64
		for i := 0; i < length; i++ {
			d := seqDig(base + i)
			wantOrder = append(wantOrder, d)
			seq++
			if i == 0 {
				records = append(records, agidstore.DelegationRecord{
					RecordDigest: d, RootAnchor: true, DelegatorID: "root", DelegateID: "d0",
					Encoded: []byte("e"), Seq: seq,
				})
			} else {
				records = append(records, agidstore.DelegationRecord{
					RecordDigest: d, ParentDigest: seqDig(base + i - 1), RootAnchor: false,
					DelegatorID: "d" + itoa(i-1), DelegateID: "d" + itoa(i),
					Encoded: []byte("e"), Seq: seq,
				})
			}
		}
		// Insert in a shuffled order.
		perm := rng.Perm(len(records))
		for _, idx := range perm {
			if err := repo.InsertDelegationRecord(ctx, tenantA, records[idx]); err != nil {
				t.Fatalf("seed %d insert: %v", seed, err)
			}
		}
		leaf := records[length-1]
		cred := "cred-" + itoa(seed)
		if err := repo.InsertIssuance(ctx, tenantA, agidstore.Issuance{
			CredentialID: cred, SubjectID: "leaf-subject",
			ChainHeadDigest: leaf.RecordDigest, ChainDigest: seqDig(base + 500),
			AgentStackDigest: seqDig(base + 600), Seq: seq + 1,
		}); err != nil {
			t.Fatalf("seed %d issuance: %v", seed, err)
		}

		chain, found, err := repo.FetchChain(ctx, tenantA, cred)
		if err != nil || !found {
			t.Fatalf("seed %d fetch: found=%v err=%v", seed, found, err)
		}
		if len(chain) != length {
			t.Fatalf("seed %d: chain len %d, want %d (gap)", seed, len(chain), length)
		}
		for i := range wantOrder {
			if !reflect.DeepEqual(chain[i].RecordDigest, wantOrder[i]) {
				t.Fatalf("seed %d: chain[%d] not in root-to-leaf order", seed, i)
			}
		}
		if !chain[0].RootAnchor {
			t.Fatalf("seed %d: chain[0] is not the root anchor", seed)
		}
	}
}

// itoa is a tiny int->string for building distinct party ids without importing fmt.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
