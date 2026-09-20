// SPDX-License-Identifier: BUSL-1.1

package translog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// proof.go carries a SELF-CONTAINED transparency-log inclusion proof (INT-18): the
// signed tree head a leaf is proven under, the RFC-6962 audit path, and the leaf
// index, together with a real verifier. It exists so the relying-party exceptional /
// recovery inclusion checks default to REAL Merkle verification against a trusted,
// signed log head — closing the earlier seam where an injected closure could satisfy
// "mandatory inclusion" without any cryptographic proof (any `func([]byte) error`
// that returned nil passed). A Proof is embedded verbatim in a record's
// InclusionProof field and verified offline.

const proofDomain = "trstctl/pcas/translog/proof/v1"

// maxInt is the largest value representable by int on this platform, used to reject
// uint64 proof fields that would wrap when narrowed to int.
const maxInt = int(^uint(0) >> 1)

// Inclusion-proof errors.
var (
	ErrProofMalformed = errors.New("translog: malformed inclusion proof")
	ErrProofUntrusted = errors.New("translog: inclusion proof lacks a trusted signed tree head")
	ErrProofSTH       = errors.New("translog: inclusion-proof tree head signature invalid")
	ErrProofInclusion = errors.New("translog: leaf is not included under the signed tree head")
)

// Proof is a self-contained inclusion proof for one leaf: the STH it is proven
// under, the audit path, and the leaf index. It carries everything a relying party
// needs to verify inclusion offline against a trusted log key — no call back to the
// log.
type Proof struct {
	STH       STH
	AuditPath [][]byte
	Index     int
}

// Prove builds a self-contained inclusion Proof for the leaf at index under the
// log's current signed head. The returned Proof's STH is signed when the log has a
// signer, so a relying party can bind it to the log's public key.
func (l *Log) Prove(index int) (Proof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < 0 || index >= len(l.lh) {
		return Proof{}, errors.New("translog: index out of range")
	}
	sth, err := l.headLocked()
	if err != nil {
		return Proof{}, err
	}
	return Proof{STH: sth, AuditPath: inclusionProof(l.lh, index), Index: index}, nil
}

// EncodeProof returns the canonical, deterministic byte encoding of a Proof, for
// embedding in a succession record's InclusionProof field.
func EncodeProof(p Proof) []byte {
	var b bytes.Buffer
	b.WriteString(proofDomain)
	writeI64(&b, int64(p.STH.TreeSize))
	writeI64(&b, p.STH.Timestamp)
	writeChunk(&b, p.STH.RootHash)
	writeChunk(&b, p.STH.Signature)
	writeI64(&b, int64(p.Index))
	writeU64(&b, uint64(len(p.AuditPath)))
	for _, h := range p.AuditPath {
		writeChunk(&b, h)
	}
	return b.Bytes()
}

// DecodeProof parses the canonical encoding produced by EncodeProof.
func DecodeProof(in []byte) (Proof, error) {
	r := &reader{b: in}
	if !r.expect(proofDomain) {
		return Proof{}, ErrProofMalformed
	}
	var p Proof
	treeSize, ok1 := r.u64()
	ts, ok2 := r.i64()
	root, ok3 := r.chunk()
	sig, ok4 := r.chunk()
	idx, ok5 := r.u64()
	n, ok6 := r.u64()
	parsedAll := ok1 && ok2 && ok3 && ok4 && ok5 && ok6
	if !parsedAll {
		return Proof{}, ErrProofMalformed
	}
	// Bound the path length to the remaining bytes so a malformed count cannot force a
	// huge allocation.
	if n > uint64(len(r.b)) {
		return Proof{}, ErrProofMalformed
	}
	// Reject values that would not survive the uint64->int narrowing below (e.g. on a
	// 32-bit build, or a crafted index > 2^63 that would become negative), rather than
	// silently wrapping into a nonsensical index/size.
	if treeSize > uint64(maxInt) || idx > uint64(maxInt) {
		return Proof{}, ErrProofMalformed
	}
	// Timestamp is a full-range two's-complement field, so it is decoded as signed
	// (r.i64) rather than range-checked: rejecting the upper half would make pre-epoch
	// heads undecodable and break EncodeProof/DecodeProof round-tripping.
	p.STH = STH{TreeSize: int(treeSize), RootHash: root, Timestamp: ts, Signature: sig}
	p.Index = int(idx)
	p.AuditPath = make([][]byte, 0, n)
	for i := uint64(0); i < n; i++ {
		h, ok := r.chunk()
		if !ok {
			return Proof{}, ErrProofMalformed
		}
		p.AuditPath = append(p.AuditPath, h)
	}
	if len(r.b) != 0 {
		return Proof{}, ErrProofMalformed
	}
	return p, nil
}

// VerifyLeafInclusion verifies that leaf is included under the Proof's SIGNED tree
// head. This is the real default that replaces any injected closure:
//
//   - sthVerifyKeyDER MUST be supplied and the STH signature MUST verify under it — an
//     unsigned or forged head is rejected (fail-closed). A relying party without a
//     trusted log key cannot soundly check inclusion, so this returns ErrProofUntrusted
//     rather than silently accepting.
//   - the RFC-6962 audit path must reconstruct the head's root for the leaf at Index of
//     a tree of TreeSize leaves.
func VerifyLeafInclusion(leaf []byte, p Proof, sthVerifyKeyDER []byte) error {
	if len(sthVerifyKeyDER) == 0 {
		return ErrProofUntrusted
	}
	if err := VerifySTH(sthVerifyKeyDER, p.STH); err != nil {
		return fmt.Errorf("%w: %v", ErrProofSTH, err)
	}
	if !VerifyInclusion(leaf, p.Index, p.STH.TreeSize, p.AuditPath, p.STH.RootHash) {
		return ErrProofInclusion
	}
	return nil
}

// VerifyEncodedInclusion decodes proofBytes and verifies that leaf is included under
// its signed head. It is the one-call form used by the relying-party exceptional /
// recovery checks.
func VerifyEncodedInclusion(leaf, proofBytes, sthVerifyKeyDER []byte) error {
	p, err := DecodeProof(proofBytes)
	if err != nil {
		return err
	}
	return VerifyLeafInclusion(leaf, p, sthVerifyKeyDER)
}

func writeU64(b *bytes.Buffer, v uint64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	b.Write(n[:])
}

// writeI64 writes v in the same eight-byte big-endian slot as writeU64, carrying
// negative values in two's complement. (*reader).i64 is its decoding inverse.
func writeI64(b *bytes.Buffer, v int64) {
	var n [8]byte
	putI64BE(&n, v)
	b.Write(n[:])
}

func writeChunk(b *bytes.Buffer, v []byte) {
	writeU64(b, uint64(len(v)))
	b.Write(v)
}

type reader struct{ b []byte }

func (r *reader) expect(s string) bool {
	if len(r.b) < len(s) || string(r.b[:len(s)]) != s {
		return false
	}
	r.b = r.b[len(s):]
	return true
}

func (r *reader) u64() (uint64, bool) {
	if len(r.b) < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.b[:8])
	r.b = r.b[8:]
	return v, true
}

// i64 reads the same eight-byte big-endian slot as u64, but reinterprets it as the
// signed value writeI64 wrote, so negative fields survive the round trip.
func (r *reader) i64() (int64, bool) {
	if len(r.b) < 8 {
		return 0, false
	}
	var w [8]byte
	copy(w[:], r.b[:8])
	r.b = r.b[8:]
	return i64BE(w), true
}

func (r *reader) chunk() ([]byte, bool) {
	n, ok := r.u64()
	if !ok || n > uint64(len(r.b)) {
		return nil, false
	}
	out := cloneBytes(r.b[:n])
	r.b = r.b[n:]
	return out, true
}
