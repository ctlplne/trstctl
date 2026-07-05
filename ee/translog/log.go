// SPDX-License-Identifier: LicenseRef-trstctl-EE

package translog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const sthDomain = "trstctl/pcas/translog/sth/v1"

// STH is a signed tree head: a commitment to the log's state at a point in time.
// The Timestamp lets a relying party later evaluate the pre-CRQC anchoring
// condition of claim 18.
type STH struct {
	TreeSize  int
	RootHash  []byte
	Timestamp int64  // unix nanoseconds
	Signature []byte // over the STH's canonical encoding (present when the log has a signer)
}

// Log is an append-only Merkle-tree transparency log for succession records.
type Log struct {
	mu     sync.Mutex
	leaves [][]byte // raw entries
	lh     [][]byte // leaf hashes
	signer crypto.Signer
	nowFn  func() time.Time
}

// New returns a Log that signs each tree head with signer (signer may be nil for
// an unsigned log used in tests).
func New(signer crypto.Signer) *Log {
	return &Log{signer: signer, nowFn: time.Now}
}

// Append adds entry to the log and returns its index and the new signed tree head.
func (l *Log) Append(entry []byte) (int, STH, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	idx := len(l.leaves)
	l.leaves = append(l.leaves, cloneBytes(entry))
	l.lh = append(l.lh, leafHash(entry))
	sth, err := l.headLocked()
	if err != nil {
		return 0, STH{}, err
	}
	return idx, sth, nil
}

// Head returns the current signed tree head.
func (l *Log) Head() (STH, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.headLocked()
}

func (l *Log) headLocked() (STH, error) {
	sth := STH{TreeSize: len(l.lh), RootHash: merkleRoot(l.lh), Timestamp: l.nowFn().UnixNano()}
	if l.signer != nil {
		sig, err := l.signer.Sign(encodeSTH(sth), crypto.SignOptions{Hash: crypto.SHA256})
		if err != nil {
			return STH{}, err
		}
		sth.Signature = sig
	}
	return sth, nil
}

// InclusionProof returns the audit path for the leaf at index and the tree size.
func (l *Log) InclusionProof(index int) (proof [][]byte, treeSize int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < 0 || index >= len(l.lh) {
		return nil, 0, errors.New("translog: index out of range")
	}
	return inclusionProof(l.lh, index), len(l.lh), nil
}

// ConsistencyProof returns the proof that a tree of oldSize is a prefix of the
// current tree, and the current tree size.
func (l *Log) ConsistencyProof(oldSize int) (proof [][]byte, treeSize int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if oldSize < 1 || oldSize > len(l.lh) {
		return nil, 0, errors.New("translog: old size out of range")
	}
	return consistencyProof(l.lh, oldSize), len(l.lh), nil
}

// VerifySTH checks the STH signature against the public key pubDER.
func VerifySTH(pubDER []byte, sth STH) error {
	return crypto.VerifyMessage(pubDER, encodeSTH(sth), sth.Signature)
}

func encodeSTH(s STH) []byte {
	var b bytes.Buffer
	b.WriteString(sthDomain)
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(s.TreeSize))
	b.Write(num[:])
	binary.BigEndian.PutUint64(num[:], uint64(s.Timestamp))
	b.Write(num[:])
	b.Write(s.RootHash)
	return b.Bytes()
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
