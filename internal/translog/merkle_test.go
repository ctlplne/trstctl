// SPDX-License-Identifier: BUSL-1.1

package translog

import (
	"fmt"
	"testing"
)

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	return out
}

func leafHashes(data [][]byte) [][]byte {
	out := make([][]byte, len(data))
	for i, d := range data {
		out[i] = leafHash(d)
	}
	return out
}

func TestMerkle_InclusionRoundTrip(t *testing.T) {
	for n := 1; n <= 33; n++ {
		data := leaves(n)
		lh := leafHashes(data)
		root := merkleRoot(lh)
		for m := 0; m < n; m++ {
			proof := inclusionProof(lh, m)
			if !VerifyInclusion(data[m], m, n, proof, root) {
				t.Fatalf("n=%d m=%d: inclusion proof failed", n, m)
			}
			// A non-member leaf must not verify at that position.
			if VerifyInclusion([]byte("not-a-member"), m, n, proof, root) {
				t.Fatalf("n=%d m=%d: non-member verified", n, m)
			}
			// A tampered proof must not verify.
			if len(proof) > 0 {
				bad := make([][]byte, len(proof))
				copy(bad, proof)
				bad[0] = append([]byte{0x00}, bad[0]...)
				if VerifyInclusion(data[m], m, n, bad, root) {
					t.Fatalf("n=%d m=%d: tampered inclusion proof verified", n, m)
				}
			}
		}
	}
}

func TestMerkle_ConsistencyRoundTrip(t *testing.T) {
	for n := 1; n <= 33; n++ {
		lh := leafHashes(leaves(n))
		newRoot := merkleRoot(lh)
		for m := 1; m <= n; m++ {
			oldRoot := merkleRoot(lh[:m])
			proof := consistencyProof(lh, m)
			if !VerifyConsistency(m, n, proof, oldRoot, newRoot) {
				t.Fatalf("n=%d m=%d: consistency proof failed", n, m)
			}
			// Tampered new root must be rejected.
			badNew := append([]byte{0x00}, newRoot...)
			if VerifyConsistency(m, n, proof, oldRoot, badNew) {
				t.Fatalf("n=%d m=%d: consistency accepted a tampered new root", n, m)
			}
			// Tampered old root must be rejected.
			badOld := append([]byte{0x00}, oldRoot...)
			if m != n && VerifyConsistency(m, n, proof, badOld, newRoot) {
				t.Fatalf("n=%d m=%d: consistency accepted a tampered old root", n, m)
			}
		}
	}
}
