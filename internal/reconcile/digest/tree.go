// SPDX-License-Identifier: BUSL-1.1

package digest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/reconcile/canon"
)

const (
	HashAlgSHA256 = "sha-256"

	leafDomain  = "xrec/leaf/v1"
	nodeDomain  = "xrec/node/v1"
	emptyDomain = "xrec/empty/v1"
)

var (
	ErrDuplicateRecordKey = errors.New("digest: duplicate record key")
	ErrRecordKey          = errors.New("digest: invalid record key")
)

// Leaf is the R-11 Merkle leaf material for one canonical record.
type Leaf struct {
	RecordKeyBytes       []byte
	CanonicalRecordBytes []byte
	Hash                 []byte
}

// Tree is an R-12 Merkle tree. levels[0] is the sorted leaf hash level; the last
// level contains the root. Odd nodes are promoted, never duplicated.
type Tree struct {
	Leaves []Leaf
	levels [][][]byte
	Root   []byte
}

// RecordKeyBytes returns the strict byte key used for leaf ordering. It mirrors
// the canonical record-key tuple order: tenant, record type, stable id.
func RecordKeyBytes(k canon.RecordKey) ([]byte, error) {
	parts := []string{k.TenantID, k.RecordType, k.StableID}
	for _, p := range parts {
		if p == "" || strings.ContainsRune(p, 0) {
			return nil, fmt.Errorf("%w: empty or NUL-containing field", ErrRecordKey)
		}
	}
	var b bytes.Buffer
	b.WriteString(parts[0])
	b.WriteByte(0)
	b.WriteString(parts[1])
	b.WriteByte(0)
	b.WriteString(parts[2])
	return b.Bytes(), nil
}

// NewLeaf builds one R-11 leaf from a canonical record.
func NewLeaf(r canon.CanonicalRecord) (Leaf, error) {
	key, err := RecordKeyBytes(r.RecordKey)
	if err != nil {
		return Leaf{}, err
	}
	rec, err := r.CanonicalBytes()
	if err != nil {
		return Leaf{}, err
	}
	return Leaf{
		RecordKeyBytes:       append([]byte(nil), key...),
		CanonicalRecordBytes: append([]byte(nil), rec...),
		Hash:                 LeafHash(key, rec),
	}, nil
}

// LeavesFromSet builds, sorts, and duplicate-checks Merkle leaves for a
// canonical set.
func LeavesFromSet(set canon.Set) ([]Leaf, error) {
	leaves := make([]Leaf, 0, len(set.Records))
	for _, rec := range set.Records {
		leaf, err := NewLeaf(rec)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, leaf)
	}
	sort.Slice(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i].RecordKeyBytes, leaves[j].RecordKeyBytes) < 0
	})
	for i := 1; i < len(leaves); i++ {
		if bytes.Equal(leaves[i-1].RecordKeyBytes, leaves[i].RecordKeyBytes) {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateRecordKey, leaves[i].RecordKeyBytes)
		}
	}
	return leaves, nil
}

// LeafHash implements R-11:
// H(0x00 || "xrec/leaf/v1" || len(record_key_bytes) || record_key_bytes ||
// canonical_record_bytes).
func LeafHash(recordKeyBytes, canonicalRecordBytes []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)
	b.WriteString(leafDomain)
	writeU64(&b, uint64(len(recordKeyBytes)))
	b.Write(recordKeyBytes)
	b.Write(canonicalRecordBytes)
	return crypto.SHA256Sum(b.Bytes())
}

// NodeHash implements R-12:
// H(0x01 || "xrec/node/v1" || left || right).
func NodeHash(left, right []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x01)
	b.WriteString(nodeDomain)
	b.Write(left)
	b.Write(right)
	return crypto.SHA256Sum(b.Bytes())
}

// EmptyRoot returns the R-12 empty-set commitment.
func EmptyRoot() []byte {
	var b bytes.Buffer
	b.WriteByte(0x00)
	b.WriteString(emptyDomain)
	return crypto.SHA256Sum(b.Bytes())
}

// BuildTree builds a sorted Merkle tree from pre-built leaves. Leaf ordering is
// total and canonical, which is what makes both inclusion and absence provable
// against the published root (XREC-claim-9).
func BuildTree(in []Leaf) (*Tree, error) {
	leaves := copyLeaves(in)
	sort.Slice(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i].RecordKeyBytes, leaves[j].RecordKeyBytes) < 0
	})
	for i := 1; i < len(leaves); i++ {
		if bytes.Equal(leaves[i-1].RecordKeyBytes, leaves[i].RecordKeyBytes) {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateRecordKey, leaves[i].RecordKeyBytes)
		}
	}
	if len(leaves) == 0 {
		return &Tree{Root: EmptyRoot()}, nil
	}
	level := make([][]byte, len(leaves))
	for i := range leaves {
		level[i] = append([]byte(nil), leaves[i].Hash...)
	}
	levels := [][][]byte{copyHashLevel(level)}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, append([]byte(nil), level[i]...))
				continue
			}
			next = append(next, NodeHash(level[i], level[i+1]))
		}
		level = next
		levels = append(levels, copyHashLevel(level))
	}
	return &Tree{Leaves: leaves, levels: levels, Root: append([]byte(nil), level[0]...)}, nil
}

// BuildTreeFromSet builds a tree directly from a canonical set.
func BuildTreeFromSet(set canon.Set) (*Tree, error) {
	leaves, err := LeavesFromSet(set)
	if err != nil {
		return nil, err
	}
	return BuildTree(leaves)
}

// ProofNode is one sibling hash in an inclusion proof. Left means the sibling
// was left of the running hash; false means it was right.
type ProofNode struct {
	Hash []byte
	Left bool
}

// InclusionProof proves one canonical record is included under a root.
type InclusionProof struct {
	RecordKeyBytes       []byte
	CanonicalRecordBytes []byte
	Siblings             []ProofNode
}

// InclusionProof returns the proof for key, when present.
func (t *Tree) InclusionProof(key []byte) (InclusionProof, bool) {
	if t == nil || len(t.Leaves) == 0 {
		return InclusionProof{}, false
	}
	idx := sort.Search(len(t.Leaves), func(i int) bool {
		return bytes.Compare(t.Leaves[i].RecordKeyBytes, key) >= 0
	})
	if idx == len(t.Leaves) || !bytes.Equal(t.Leaves[idx].RecordKeyBytes, key) {
		return InclusionProof{}, false
	}
	leaf := t.Leaves[idx]
	proof := InclusionProof{
		RecordKeyBytes:       append([]byte(nil), leaf.RecordKeyBytes...),
		CanonicalRecordBytes: append([]byte(nil), leaf.CanonicalRecordBytes...),
	}
	pos := idx
	for levelIdx := 0; levelIdx < len(t.levels)-1; levelIdx++ {
		level := t.levels[levelIdx]
		if pos%2 == 0 {
			if pos+1 < len(level) {
				proof.Siblings = append(proof.Siblings, ProofNode{Hash: append([]byte(nil), level[pos+1]...)})
			}
		} else {
			proof.Siblings = append(proof.Siblings, ProofNode{Hash: append([]byte(nil), level[pos-1]...), Left: true})
		}
		pos /= 2
	}
	return proof, true
}

// VerifyInclusion verifies this proof against root.
func (p InclusionProof) VerifyInclusion(root []byte) bool {
	if len(p.RecordKeyBytes) == 0 || len(p.CanonicalRecordBytes) == 0 {
		return false
	}
	cur := LeafHash(p.RecordKeyBytes, p.CanonicalRecordBytes)
	for _, sib := range p.Siblings {
		if len(sib.Hash) != 32 {
			return false
		}
		if sib.Left {
			cur = NodeHash(sib.Hash, cur)
		} else {
			cur = NodeHash(cur, sib.Hash)
		}
	}
	return bytes.Equal(cur, root)
}

// ProofLeaf is a bracketing leaf carried by an absence proof.
type ProofLeaf struct {
	RecordKeyBytes       []byte
	CanonicalRecordBytes []byte
	Proof                InclusionProof
}

// AbsenceProof proves a target key is absent by presenting adjacent bracketing
// leaves, or a single boundary leaf at an extreme.
type AbsenceProof struct {
	TargetKeyBytes []byte
	Lower          *ProofLeaf
	Upper          *ProofLeaf
}

// AbsenceProof returns a proof that target is absent. The bool is false if the
// key is present.
func (t *Tree) AbsenceProof(target []byte) (AbsenceProof, bool) {
	proof := AbsenceProof{TargetKeyBytes: append([]byte(nil), target...)}
	if t == nil || len(t.Leaves) == 0 {
		return proof, true
	}
	pos := sort.Search(len(t.Leaves), func(i int) bool {
		return bytes.Compare(t.Leaves[i].RecordKeyBytes, target) >= 0
	})
	if pos < len(t.Leaves) && bytes.Equal(t.Leaves[pos].RecordKeyBytes, target) {
		return AbsenceProof{}, false
	}
	if pos > 0 {
		proof.Lower = t.proofLeaf(pos - 1)
	}
	if pos < len(t.Leaves) {
		proof.Upper = t.proofLeaf(pos)
	}
	return proof, true
}

// VerifyAbsence verifies this absence proof against root.
func (p AbsenceProof) VerifyAbsence(root []byte) bool {
	if len(p.TargetKeyBytes) == 0 {
		return false
	}
	if p.Lower == nil && p.Upper == nil {
		return bytes.Equal(root, EmptyRoot())
	}
	if p.Lower != nil {
		if bytes.Compare(p.Lower.RecordKeyBytes, p.TargetKeyBytes) >= 0 || !p.Lower.Proof.VerifyInclusion(root) {
			return false
		}
	}
	if p.Upper != nil {
		if bytes.Compare(p.TargetKeyBytes, p.Upper.RecordKeyBytes) >= 0 || !p.Upper.Proof.VerifyInclusion(root) {
			return false
		}
	}
	if p.Lower != nil && p.Upper != nil && bytes.Compare(p.Lower.RecordKeyBytes, p.Upper.RecordKeyBytes) >= 0 {
		return false
	}
	return true
}

func (t *Tree) proofLeaf(idx int) *ProofLeaf {
	proof, _ := t.InclusionProof(t.Leaves[idx].RecordKeyBytes)
	return &ProofLeaf{
		RecordKeyBytes:       append([]byte(nil), t.Leaves[idx].RecordKeyBytes...),
		CanonicalRecordBytes: append([]byte(nil), t.Leaves[idx].CanonicalRecordBytes...),
		Proof:                proof,
	}
}

func copyLeaves(in []Leaf) []Leaf {
	out := make([]Leaf, len(in))
	for i, l := range in {
		out[i] = Leaf{
			RecordKeyBytes:       append([]byte(nil), l.RecordKeyBytes...),
			CanonicalRecordBytes: append([]byte(nil), l.CanonicalRecordBytes...),
			Hash:                 append([]byte(nil), l.Hash...),
		}
	}
	return out
}

func copyHashLevel(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func writeU64(b *bytes.Buffer, v uint64) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	b.Write(tmp[:])
}
