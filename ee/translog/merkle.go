// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package translog is the proprietary append-only Merkle-tree transparency log for
// PCAS succession records (RFC 6962-style), plus the misissuance-proof builder.
// All hashing routes through the core internal/crypto AN-3 boundary; this package
// imports no crypto/* directly.
package translog

import (
	"bytes"

	"trstctl.com/trstctl/internal/crypto"
)

// RFC 6962 domain-separated hashing, routed through the core crypto boundary.
func leafHash(leaf []byte) []byte {
	return crypto.SHA256Sum(append([]byte{0x00}, leaf...))
}

func nodeHash(l, r []byte) []byte {
	b := make([]byte, 0, 1+len(l)+len(r))
	b = append(b, 0x01)
	b = append(b, l...)
	b = append(b, r...)
	return crypto.SHA256Sum(b)
}

// largestPowerOfTwoLessThan returns the largest 2^k strictly less than n (n >= 2).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k < n {
		k <<= 1
	}
	return k >> 1
}

// merkleRoot is the RFC 6962 Merkle Tree Hash over the given leaf hashes.
func merkleRoot(leafHashes [][]byte) []byte {
	n := len(leafHashes)
	if n == 0 {
		return crypto.SHA256Sum(nil)
	}
	if n == 1 {
		return leafHashes[0]
	}
	k := largestPowerOfTwoLessThan(n)
	return nodeHash(merkleRoot(leafHashes[:k]), merkleRoot(leafHashes[k:]))
}

// inclusionProof returns the RFC 6962 audit path for the leaf at index m in the
// tree of the given leaf hashes (deepest sibling first).
func inclusionProof(leafHashes [][]byte, m int) [][]byte {
	n := len(leafHashes)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(inclusionProof(leafHashes[:k], m), merkleRoot(leafHashes[k:]))
	}
	return append(inclusionProof(leafHashes[k:], m-k), merkleRoot(leafHashes[:k]))
}

// VerifyInclusion checks that leaf is the m-th of n leaves under root, using proof.
func VerifyInclusion(leaf []byte, m, n int, proof [][]byte, root []byte) bool {
	if m >= n || n == 0 {
		return false
	}
	h, rest, ok := rootFromInclusion(leafHash(leaf), m, n, proof)
	return ok && len(rest) == 0 && bytes.Equal(h, root)
}

// rootFromInclusion recomputes the tree root from a leaf hash and its audit path,
// mirroring inclusionProof exactly: the deeper subtree's path is the prefix and the
// current level's sibling is consumed after it.
func rootFromInclusion(h []byte, m, n int, proof [][]byte) ([]byte, [][]byte, bool) {
	if n == 1 {
		return h, proof, true
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		hh, rest, ok := rootFromInclusion(h, m, k, proof)
		if !ok || len(rest) == 0 {
			return nil, nil, false
		}
		return nodeHash(hh, rest[0]), rest[1:], true
	}
	hh, rest, ok := rootFromInclusion(h, m-k, n-k, proof)
	if !ok || len(rest) == 0 {
		return nil, nil, false
	}
	return nodeHash(rest[0], hh), rest[1:], true
}

// consistencyProof returns the RFC 6962 consistency proof that a tree of the given
// leaf hashes (size n) is an extension of its first m leaves.
func consistencyProof(leafHashes [][]byte, m int) [][]byte {
	return subProof(m, leafHashes, true)
}

func subProof(m int, leafHashes [][]byte, b bool) [][]byte {
	n := len(leafHashes)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{merkleRoot(leafHashes)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subProof(m, leafHashes[:k], b), merkleRoot(leafHashes[k:]))
	}
	return append(subProof(m-k, leafHashes[k:], false), merkleRoot(leafHashes[:k]))
}

// VerifyConsistency checks the RFC 6962 consistency proof between an old tree of
// size m (root oldRoot) and a new tree of size n (root newRoot).
func VerifyConsistency(m, n int, proof [][]byte, oldRoot, newRoot []byte) bool {
	if m == 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && bytes.Equal(oldRoot, newRoot)
	}
	node, last := m-1, n-1
	for node%2 == 1 {
		node /= 2
		last /= 2
	}
	p := 0
	var fr, sr []byte
	if node > 0 {
		if len(proof) == 0 {
			return false
		}
		fr, sr = proof[0], proof[0]
		p = 1
	} else {
		fr, sr = oldRoot, oldRoot
	}
	for node > 0 {
		if node%2 == 1 {
			if p >= len(proof) {
				return false
			}
			fr = nodeHash(proof[p], fr)
			sr = nodeHash(proof[p], sr)
			p++
		} else if node < last {
			if p >= len(proof) {
				return false
			}
			sr = nodeHash(sr, proof[p])
			p++
		}
		node /= 2
		last /= 2
	}
	for last > 0 {
		if p >= len(proof) {
			return false
		}
		sr = nodeHash(sr, proof[p])
		p++
		last /= 2
	}
	return p == len(proof) && bytes.Equal(fr, oldRoot) && bytes.Equal(sr, newRoot)
}
