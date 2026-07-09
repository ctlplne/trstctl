// SPDX-License-Identifier: LicenseRef-trstctl-EE

package aggregate

import (
	"bytes"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/ee/decommission/record"
	"trstctl.com/trstctl/internal/crypto"
)

type MerkleSibling struct {
	Left   bool   `json:"left"`
	Digest []byte `json:"digest"`
}

type LeafProof struct {
	LeafIndex int             `json:"leaf_index"`
	Leaf      Leaf            `json:"leaf"`
	Siblings  []MerkleSibling `json:"siblings"`
}

func LeafRoot(leaves []Leaf) ([]byte, error) {
	root, _, err := leafRootAndProofs(leaves)
	return root, err
}

func ProofForKey(rec SignedRecord, stableKeyID string) (LeafProof, error) {
	leaves := normalizeLeaves(rec.Commitment.Leaves)
	_, proofs, err := leafRootAndProofs(leaves)
	if err != nil {
		return LeafProof{}, err
	}
	for i, leaf := range leaves {
		if leaf.StableKeyID == stableKeyID {
			return proofs[i], nil
		}
	}
	return LeafProof{}, fmt.Errorf("%w: key %q is not a committed leaf", ErrUnverified, stableKeyID)
}

func VerifyLeafDescent(agg SignedRecord, proof LeafProof, perKey record.SignedRecord, aggregateTrust, perKeyTrust crypto.PublicKey) error {
	if err := VerifyRecord(agg, aggregateTrust); err != nil {
		return err
	}
	if err := record.VerifyRecord(perKey, perKeyTrust); err != nil {
		return fmt.Errorf("%w: per-key record did not verify: %v", ErrUnverified, err)
	}
	vector, err := record.Vector(perKey.Commitment.StableKeyID, perKey)
	if err != nil {
		return err
	}
	leaf := normalizeLeaves([]Leaf{proof.Leaf})[0]
	if leaf.TenantID != agg.Commitment.TenantID ||
		leaf.TenantID != perKey.Commitment.TenantID ||
		leaf.StableKeyID != perKey.Commitment.StableKeyID ||
		leaf.FinalEpoch != perKey.Commitment.FinalEpoch ||
		!bytes.Equal(leaf.RecordDigest, vector.EncodedRecordDigest) ||
		!bytes.Equal(leaf.CommitmentDigest, perKey.CommitmentDigest) {
		return fmt.Errorf("%w: proof leaf does not match per-key destruction record", ErrUnverified)
	}
	if proof.LeafIndex < 0 || proof.LeafIndex >= len(agg.Commitment.Leaves) {
		return fmt.Errorf("%w: proof leaf index outside aggregate", ErrUnverified)
	}
	if !equalLeaf(normalizeLeaves([]Leaf{agg.Commitment.Leaves[proof.LeafIndex]})[0], leaf) {
		return fmt.Errorf("%w: proof leaf is not at the committed deterministic index", ErrUnverified)
	}
	root, err := rootFromProof(leaf, proof.Siblings)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, agg.Commitment.LeafRoot) {
		return fmt.Errorf("%w: per-key leaf does not descend to aggregate root", ErrUnverified)
	}
	return nil
}

func leafRootAndProofs(leaves []Leaf) ([]byte, []LeafProof, error) {
	leaves = normalizeLeaves(leaves)
	if len(leaves) == 0 {
		return nil, nil, fmt.Errorf("%w: at least one leaf is required", ErrInvalidRecord)
	}
	proofs := make([]LeafProof, len(leaves))
	nodes := make([]treeNode, len(leaves))
	for i, leaf := range leaves {
		digest, err := leafDigest(leaf)
		if err != nil {
			return nil, nil, err
		}
		nodes[i] = treeNode{digest: digest, indexes: []int{i}}
		proofs[i] = LeafProof{LeafIndex: i, Leaf: leaf}
	}
	for len(nodes) > 1 {
		next := make([]treeNode, 0, (len(nodes)+1)/2)
		for i := 0; i < len(nodes); i += 2 {
			if i+1 == len(nodes) {
				next = append(next, nodes[i])
				continue
			}
			left := nodes[i]
			right := nodes[i+1]
			for _, idx := range left.indexes {
				proofs[idx].Siblings = append(proofs[idx].Siblings, MerkleSibling{Digest: cloneBytes(right.digest)})
			}
			for _, idx := range right.indexes {
				proofs[idx].Siblings = append(proofs[idx].Siblings, MerkleSibling{Left: true, Digest: cloneBytes(left.digest)})
			}
			next = append(next, treeNode{digest: nodeDigest(left.digest, right.digest), indexes: append(append([]int(nil), left.indexes...), right.indexes...)})
		}
		nodes = next
	}
	return cloneBytes(nodes[0].digest), proofs, nil
}

type treeNode struct {
	digest  []byte
	indexes []int
}

func rootFromProof(leaf Leaf, siblings []MerkleSibling) ([]byte, error) {
	root, err := leafDigest(leaf)
	if err != nil {
		return nil, err
	}
	for _, sibling := range siblings {
		if len(sibling.Digest) == 0 {
			return nil, fmt.Errorf("%w: empty proof sibling", ErrUnverified)
		}
		if sibling.Left {
			root = nodeDigest(sibling.Digest, root)
		} else {
			root = nodeDigest(root, sibling.Digest)
		}
	}
	return root, nil
}

func leafDigest(leaf Leaf) ([]byte, error) {
	leaf = normalizeLeaves([]Leaf{leaf})[0]
	if leaf.TenantID == "" || leaf.StableKeyID == "" || leaf.FinalEpoch == 0 || len(leaf.RecordDigest) == 0 || len(leaf.CommitmentDigest) == 0 {
		return nil, fmt.Errorf("%w: incomplete leaf", ErrInvalidRecord)
	}
	body := struct {
		Domain string `json:"domain"`
		Leaf   Leaf   `json:"leaf"`
	}{Domain: "trstctl/vdec/aggregate/leaf/v1", Leaf: leaf}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("aggregate decommissioning record: encode leaf digest: %w", err)
	}
	return crypto.SHA256Sum(append([]byte{0}, raw...)), nil
}

func nodeDigest(left, right []byte) []byte {
	body := make([]byte, 0, 1+len(left)+len(right))
	body = append(body, 1)
	body = append(body, left...)
	body = append(body, right...)
	return crypto.SHA256Sum(body)
}

func equalLeaf(a, b Leaf) bool {
	return a.TenantID == b.TenantID &&
		a.StableKeyID == b.StableKeyID &&
		a.FinalEpoch == b.FinalEpoch &&
		a.KeyClass == b.KeyClass &&
		bytes.Equal(a.RecordDigest, b.RecordDigest) &&
		bytes.Equal(a.CommitmentDigest, b.CommitmentDigest)
}
