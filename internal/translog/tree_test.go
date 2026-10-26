// SPDX-License-Identifier: BUSL-1.1

package translog_test

import (
	"bytes"
	"fmt"
	"testing"

	"trstctl.com/trstctl/internal/translog"
)

// A Tree built from stored entries answers exactly as a Log appended with the
// same entries: the same root, inclusion paths that verify, and consistency
// with every prefix.
func TestTreeMatchesTheAppendLog(t *testing.T) {
	for _, size := range []int{1, 2, 3, 7, 8, 13} {
		var entries [][]byte
		log := translog.New(nil)
		for i := 0; i < size; i++ {
			entry := []byte(fmt.Sprintf("entry-%d", i))
			entries = append(entries, entry)
			if _, _, err := log.Append(entry); err != nil {
				t.Fatal(err)
			}
		}
		tree := translog.NewTree(entries)
		head, err := log.Head()
		if err != nil {
			t.Fatal(err)
		}
		if tree.Size() != size || !bytes.Equal(tree.Root(), head.RootHash) {
			t.Fatalf("size %d: tree root differs from the log's", size)
		}
		for i, entry := range entries {
			path, err := tree.InclusionProof(i)
			if err != nil || !translog.VerifyInclusion(entry, i, size, path, tree.Root()) {
				t.Fatalf("size %d: entry %d inclusion = %v", size, i, err)
			}
		}
		for old := 1; old <= size; old++ {
			prefix := translog.NewTree(entries[:old])
			path, err := tree.ConsistencyProof(old)
			if err != nil || !translog.VerifyConsistency(old, size, path, prefix.Root(), tree.Root()) {
				t.Fatalf("size %d: consistency from %d = %v", size, old, err)
			}
		}
		if _, err := tree.InclusionProof(size); err == nil {
			t.Fatal("an index past the tree was proven")
		}
		if _, err := tree.ConsistencyProof(0); err == nil {
			t.Fatal("consistency from an empty prefix was proven")
		}
	}
}
