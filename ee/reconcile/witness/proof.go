// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness

import (
	"bytes"

	"trstctl.com/trstctl/ee/reconcile/digest"
)

type ProofNode struct {
	Hash []byte `json:"hash"`
	Left bool   `json:"left,omitempty"`
}

type InclusionProof struct {
	RecordKeyBytes       []byte      `json:"record_key_bytes"`
	CanonicalRecordBytes []byte      `json:"canonical_record_bytes"`
	Siblings             []ProofNode `json:"siblings,omitempty"`
}

type BracketProof struct {
	RecordKeyBytes []byte      `json:"record_key_bytes"`
	LeafHash       []byte      `json:"leaf_hash"`
	Siblings       []ProofNode `json:"siblings,omitempty"`
}

type AbsenceProof struct {
	TargetKeyBytes []byte        `json:"target_key_bytes"`
	Lower          *BracketProof `json:"lower,omitempty"`
	Upper          *BracketProof `json:"upper,omitempty"`
}

func (p InclusionProof) Verify(root []byte) bool {
	return digest.InclusionProof{
		RecordKeyBytes:       append([]byte(nil), p.RecordKeyBytes...),
		CanonicalRecordBytes: append([]byte(nil), p.CanonicalRecordBytes...),
		Siblings:             digestNodes(p.Siblings),
	}.VerifyInclusion(root)
}

func (p BracketProof) Verify(root []byte) bool {
	if len(p.RecordKeyBytes) == 0 || len(p.LeafHash) != 32 {
		return false
	}
	cur := append([]byte(nil), p.LeafHash...)
	for _, sib := range p.Siblings {
		if len(sib.Hash) != 32 {
			return false
		}
		if sib.Left {
			cur = digest.NodeHash(sib.Hash, cur)
		} else {
			cur = digest.NodeHash(cur, sib.Hash)
		}
	}
	return bytes.Equal(cur, root)
}

func (p AbsenceProof) Verify(root []byte) bool {
	if len(p.TargetKeyBytes) == 0 {
		return false
	}
	if p.Lower == nil && p.Upper == nil {
		return bytes.Equal(root, digest.EmptyRoot())
	}
	if p.Lower != nil {
		if bytes.Compare(p.Lower.RecordKeyBytes, p.TargetKeyBytes) >= 0 || !p.Lower.Verify(root) {
			return false
		}
	}
	if p.Upper != nil {
		if bytes.Compare(p.TargetKeyBytes, p.Upper.RecordKeyBytes) >= 0 || !p.Upper.Verify(root) {
			return false
		}
	}
	if p.Lower != nil && p.Upper != nil && bytes.Compare(p.Lower.RecordKeyBytes, p.Upper.RecordKeyBytes) >= 0 {
		return false
	}
	return true
}

func inclusionFromDigest(p digest.InclusionProof) InclusionProof {
	return InclusionProof{
		RecordKeyBytes:       append([]byte(nil), p.RecordKeyBytes...),
		CanonicalRecordBytes: append([]byte(nil), p.CanonicalRecordBytes...),
		Siblings:             proofNodes(p.Siblings),
	}
}

func absenceFromDigest(p digest.AbsenceProof) *AbsenceProof {
	out := &AbsenceProof{TargetKeyBytes: append([]byte(nil), p.TargetKeyBytes...)}
	if p.Lower != nil {
		out.Lower = bracketFromDigest(*p.Lower)
	}
	if p.Upper != nil {
		out.Upper = bracketFromDigest(*p.Upper)
	}
	return out
}

func bracketFromDigest(p digest.ProofLeaf) *BracketProof {
	return &BracketProof{
		RecordKeyBytes: append([]byte(nil), p.RecordKeyBytes...),
		LeafHash:       digest.LeafHash(p.RecordKeyBytes, p.CanonicalRecordBytes),
		Siblings:       proofNodes(p.Proof.Siblings),
	}
}

func proofNodes(in []digest.ProofNode) []ProofNode {
	out := make([]ProofNode, len(in))
	for i, n := range in {
		out[i] = ProofNode{Hash: append([]byte(nil), n.Hash...), Left: n.Left}
	}
	return out
}

func digestNodes(in []ProofNode) []digest.ProofNode {
	out := make([]digest.ProofNode, len(in))
	for i, n := range in {
		out[i] = digest.ProofNode{Hash: append([]byte(nil), n.Hash...), Left: n.Left}
	}
	return out
}
