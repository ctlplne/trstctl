// SPDX-License-Identifier: BUSL-1.1

package translog

import "errors"

// Tree is a fixed RFC 6962 Merkle tree over a list of entries, for callers
// that rebuild a log from its stored entries to answer one request. Unlike Log,
// it hashes each entry once instead of recomputing the root on every append,
// and it signs nothing: the caller decides what statement covers the root.
type Tree struct {
	leafHashes [][]byte
}

// NewTree builds the tree over entries, in order.
func NewTree(entries [][]byte) *Tree {
	t := &Tree{leafHashes: make([][]byte, len(entries))}
	for i, entry := range entries {
		t.leafHashes[i] = leafHash(entry)
	}
	return t
}

// Size is the number of entries.
func (t *Tree) Size() int { return len(t.leafHashes) }

// Root is the RFC 6962 Merkle Tree Hash.
func (t *Tree) Root() []byte { return merkleRoot(t.leafHashes) }

// InclusionProof is the audit path of the entry at index; VerifyInclusion checks
// it against Root.
func (t *Tree) InclusionProof(index int) ([][]byte, error) {
	if index < 0 || index >= len(t.leafHashes) {
		return nil, errors.New("translog: index out of range")
	}
	return inclusionProof(t.leafHashes, index), nil
}

// ConsistencyProof proves the tree extends its first oldSize entries;
// VerifyConsistency checks it.
func (t *Tree) ConsistencyProof(oldSize int) ([][]byte, error) {
	if oldSize < 1 || oldSize > len(t.leafHashes) {
		return nil, errors.New("translog: old size out of range")
	}
	return consistencyProof(t.leafHashes, oldSize), nil
}
