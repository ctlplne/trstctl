// SPDX-License-Identifier: LicenseRef-trstctl-EE

package background

import (
	"bytes"
	"testing"

	pcasstore "trstctl.com/trstctl/ee/succession/store"
	"trstctl.com/trstctl/ee/translog"
)

// TestTransparencyHead_RealRootNotSynthesized verifies that the checkpoint worker
// binds the actual Merkle head of the tenant's transparency log (PCAS-audit
// E-3b): the head is a pure function of the record set, matches an independent
// translog build leaf-for-leaf, advances its tree size with the record count, and
// is NOT the earlier synthesized "pcas-log-head:..." placeholder.
func TestTransparencyHead_RealRootNotSynthesized(t *testing.T) {
	records := []pcasstore.Record{
		{IdentityID: "spiffe://acme/a", Epoch: 1, Encoded: []byte(`{"r":"a1"}`)},
		{IdentityID: "spiffe://acme/a", Epoch: 2, Encoded: []byte(`{"r":"a2"}`)},
		{IdentityID: "spiffe://acme/b", Epoch: 1, Encoded: []byte(`{"r":"b1"}`)},
	}

	head, err := transparencyHead(records)
	if err != nil {
		t.Fatalf("transparencyHead: %v", err)
	}
	if head.TreeSize != len(records) {
		t.Fatalf("tree size = %d, want %d", head.TreeSize, len(records))
	}
	if len(head.RootHash) == 0 {
		t.Fatal("root hash is empty")
	}

	// Independent rebuild over the same encoded leaves must yield the same root:
	// the head is deterministic and reproducible by any verifier holding the
	// records (the property equivocation detection rests on).
	indep := translog.New(nil)
	for _, r := range records {
		if _, _, err := indep.Append(r.Encoded); err != nil {
			t.Fatalf("independent append: %v", err)
		}
	}
	indepHead, err := indep.Head()
	if err != nil {
		t.Fatalf("independent head: %v", err)
	}
	if !bytes.Equal(head.RootHash, indepHead.RootHash) {
		t.Fatalf("root hash mismatch:\n worker=%x\n indep =%x", head.RootHash, indepHead.RootHash)
	}
}

// TestTransparencyHead_DivergentRecordsDivergentHead verifies the equivocation
// property claim 29 relies on: two record sets that differ in even one leaf, at
// the same tree size, produce different bound heads.
func TestTransparencyHead_DivergentRecordsDivergentHead(t *testing.T) {
	base := []pcasstore.Record{
		{IdentityID: "spiffe://acme/a", Epoch: 1, Encoded: []byte(`{"r":"a1"}`)},
		{IdentityID: "spiffe://acme/a", Epoch: 2, Encoded: []byte(`{"r":"a2"}`)},
	}
	forked := []pcasstore.Record{
		{IdentityID: "spiffe://acme/a", Epoch: 1, Encoded: []byte(`{"r":"a1"}`)},
		{IdentityID: "spiffe://acme/a", Epoch: 2, Encoded: []byte(`{"r":"a2-FORK"}`)},
	}

	h1, err := transparencyHead(base)
	if err != nil {
		t.Fatalf("base head: %v", err)
	}
	h2, err := transparencyHead(forked)
	if err != nil {
		t.Fatalf("forked head: %v", err)
	}
	if h1.TreeSize != h2.TreeSize {
		t.Fatalf("tree sizes differ (%d vs %d); test intends equal size, different root", h1.TreeSize, h2.TreeSize)
	}
	if bytes.Equal(h1.RootHash, h2.RootHash) {
		t.Fatal("divergent record sets produced the same log head; equivocation would be undetectable")
	}
}

// TestTransparencyHead_Empty verifies the empty-log case is safe (no panic) and
// returns the well-defined empty-tree head.
func TestTransparencyHead_Empty(t *testing.T) {
	head, err := transparencyHead(nil)
	if err != nil {
		t.Fatalf("empty transparencyHead: %v", err)
	}
	if head.TreeSize != 0 {
		t.Fatalf("empty tree size = %d, want 0", head.TreeSize)
	}
}
