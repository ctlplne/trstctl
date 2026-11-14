// SPDX-License-Identifier: BUSL-1.1

package store

import "testing"

// Q4-L4: the graph's chain walk is root first, and a chain with a missing
// parent, a loop, or no root anchor is broken rather than partial.
func TestWalkChainForTheGraphQ4L4(t *testing.T) {
	t.Parallel()
	rec := func(digest, parent string, root bool) DelegationRecord {
		r := DelegationRecord{RecordDigest: []byte(digest), RootAnchor: root, DelegatorID: digest + "-from", DelegateID: digest + "-to"}
		if parent != "" {
			r.ParentDigest = []byte(parent)
		}
		return r
	}
	records := map[string]DelegationRecord{}
	for _, r := range []DelegationRecord{
		rec("root", "", true), rec("mid", "root", false), rec("leaf", "mid", false),
		rec("orphan", "gone", false), rec("loop-a", "loop-b", false), rec("loop-b", "loop-a", false), rec("dangling", "", false),
	} {
		records[string(r.RecordDigest)] = r
	}
	chain, broken := walkChain(records, []byte("leaf"))
	if broken || len(chain) != 3 || string(chain[0].RecordDigest) != "root" || string(chain[2].RecordDigest) != "leaf" {
		t.Fatalf("leaf chain = %v broken=%t", chain, broken)
	}
	for _, head := range []string{"orphan", "loop-a", "dangling", "missing"} {
		if chain, broken := walkChain(records, []byte(head)); !broken || chain != nil {
			t.Fatalf("%s: chain %v, broken %t; want broken and no partial chain", head, chain, broken)
		}
	}
}
