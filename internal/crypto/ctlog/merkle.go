// SPDX-License-Identifier: BUSL-1.1

package ctlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// MerkleLeafHash is the RFC 6962 §2.1 hash of one log entry:
// SHA-256(0x00 || MerkleTreeLeaf).
func MerkleLeafHash(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(leaf)
	return h.Sum(nil)
}

func merkleNodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// SignedTreeHead is a log's get-sth answer (RFC 6962 §4.3).
type SignedTreeHead struct {
	TreeSize  uint64
	Timestamp uint64
	RootHash  []byte
	Signature []byte
}

// ParseSignedTreeHead parses a get-sth body keeping what its signature covers.
func ParseSignedTreeHead(body []byte) (SignedTreeHead, error) {
	var raw struct {
		TreeSize  int64  `json:"tree_size"`
		Timestamp uint64 `json:"timestamp"`
		Root      string `json:"sha256_root_hash"`
		Signature string `json:"tree_head_signature"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return SignedTreeHead{}, fmt.Errorf("ctlog: parse signed tree head: %w", err)
	}
	root, err := base64.StdEncoding.DecodeString(raw.Root)
	if err != nil || len(root) != sha256.Size || raw.TreeSize < 0 {
		return SignedTreeHead{}, errors.New("ctlog: signed tree head carries no SHA-256 root")
	}
	signature, err := base64.StdEncoding.DecodeString(raw.Signature)
	if err != nil {
		return SignedTreeHead{}, errors.New("ctlog: signed tree head signature is malformed")
	}
	return SignedTreeHead{TreeSize: uint64(raw.TreeSize), Timestamp: raw.Timestamp, RootHash: root, Signature: signature}, nil // #nosec G115 -- non-negative checked above (CWE-190)
}

// VerifySignedTreeHead checks a tree head's signature with the log key.
func VerifySignedTreeHead(sth SignedTreeHead, logKeySPKI []byte) error {
	var signed []byte
	signed = append(signed, sctVersionV1, signatureTypeTreeHash)
	signed = appendU64(signed, sth.Timestamp)
	signed = appendU64(signed, sth.TreeSize)
	signed = append(signed, sth.RootHash...)
	if err := verifyDigitallySigned(logKeySPKI, signed, sth.Signature); err != nil {
		return fmt.Errorf("ctlog: signed tree head: %w", err)
	}
	return nil
}

// InclusionProof is a get-proof-by-hash answer (RFC 6962 §4.5).
type InclusionProof struct {
	LeafIndex uint64
	AuditPath [][]byte
}

// maxAuditPath bounds a proof: a tree of 2^64 entries needs 64 hashes.
const maxAuditPath = 64

// ParseInclusionProof parses a get-proof-by-hash body.
func ParseInclusionProof(body []byte) (InclusionProof, error) {
	var raw struct {
		LeafIndex int64    `json:"leaf_index"`
		AuditPath []string `json:"audit_path"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return InclusionProof{}, fmt.Errorf("ctlog: parse inclusion proof: %w", err)
	}
	if raw.LeafIndex < 0 || len(raw.AuditPath) > maxAuditPath {
		return InclusionProof{}, errors.New("ctlog: inclusion proof is out of bounds")
	}
	out := InclusionProof{LeafIndex: uint64(raw.LeafIndex)} // #nosec G115 -- non-negative checked above (CWE-190)
	for _, encoded := range raw.AuditPath {
		node, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(node) != sha256.Size {
			return InclusionProof{}, errors.New("ctlog: inclusion proof node is not a SHA-256 hash")
		}
		out.AuditPath = append(out.AuditPath, node)
	}
	return out, nil
}

// VerifyInclusion checks that leafHash sits at index in a tree of treeSize
// entries whose root is rootHash, by the RFC 9162 §2.1.3.2 audit path
// algorithm (the same path RFC 6962 serves).
func VerifyInclusion(leafHash []byte, index, treeSize uint64, auditPath [][]byte, rootHash []byte) error {
	if index >= treeSize {
		return errors.New("ctlog: leaf index is outside the tree")
	}
	fn, sn := index, treeSize-1
	r := leafHash
	for _, p := range auditPath {
		if sn == 0 {
			return errors.New("ctlog: inclusion proof is longer than the tree")
		}
		if fn&1 == 1 || fn == sn {
			r = merkleNodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = merkleNodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytes.Equal(r, rootHash) {
		return errors.New("ctlog: inclusion proof does not lead to the signed root")
	}
	return nil
}
