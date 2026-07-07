// SPDX-License-Identifier: LicenseRef-trstctl-EE

package store_test

import (
	"context"
	"encoding/binary"
	"math/rand"
	"reflect"
	"testing"

	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
)

// seqDig makes a distinct 32-byte digest for an integer so chain nodes have unique
// ids in the property test.
func seqDig(i int) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b, uint64(i)+1)
	return b
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
		rng := rand.New(rand.NewSource(int64(seed)))
		length := 1 + rng.Intn(6) // 1..6 records

		base := seed * 100
		var records []agidstore.DelegationRecord
		var wantOrder [][]byte
		for i := 0; i < length; i++ {
			d := seqDig(base + i)
			wantOrder = append(wantOrder, d)
			if i == 0 {
				records = append(records, agidstore.DelegationRecord{
					RecordDigest: d, RootAnchor: true, DelegatorID: "root", DelegateID: "d0",
					Encoded: []byte("e"), Seq: uint64(i + 1),
				})
			} else {
				records = append(records, agidstore.DelegationRecord{
					RecordDigest: d, ParentDigest: seqDig(base + i - 1), RootAnchor: false,
					DelegatorID: "d" + itoa(i-1), DelegateID: "d" + itoa(i),
					Encoded: []byte("e"), Seq: uint64(i + 1),
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
			AgentStackDigest: seqDig(base + 600), Seq: uint64(length + 1),
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
