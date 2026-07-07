// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"bytes"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// recordPrefix domain-separates the canonical delegation-record encoding.
const recordPrefix = "agid/delegation/record/v1"

// KeyRef references the delegator's signing key without carrying key material. ID is
// an opaque, tenant-scoped key identifier; Algorithm names the signature algorithm.
// It is a reference only — no private (or public) key bytes live here (AN-8: this
// package never holds key material; verification takes the public key DER out of
// band, via crypto.Signer.Public()).
type KeyRef struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
}

// Record is a single delegation record in a chain (card §3.1): the delegator's id and
// key reference, the delegate's id, the conferred authority set, the delegation depth
// remaining, the validity window, the parent-record hash (or the root-anchor marker),
// an optional task-envelope digest, and the delegator's signature over the canonical
// serialization of the preceding fields.
//
// A record is either root-anchored (RootAnchor true, ParentDigest empty) or linked
// (RootAnchor false, ParentDigest set) — never both and never neither
// (ValidateLinkage). The linkage form is bound into the canonical bytes, so a
// root-anchored record and a parent-linked one never share a digest.
//
// This structure carries no issuance key and mints nothing; Sign only attests the
// record's own contents with the delegator's key. The in-signer verification that
// consumes a chain of these records before a key operation is AGID-04 (INV-A1).
type Record struct {
	TenantID       string    `json:"tenant_id"` // AN-1
	DelegatorID    string    `json:"delegator_id"`
	DelegatorKey   KeyRef    `json:"delegator_key"`
	DelegateID     string    `json:"delegate_id"`
	Authority      Authority `json:"authority"`
	DepthRemaining uint32    `json:"depth_remaining"`
	Validity       Window    `json:"validity"`
	RootAnchor     bool      `json:"root_anchor,omitempty"`   // true iff this record anchors a chain root
	ParentDigest   []byte    `json:"parent_digest,omitempty"` // digest of the parent record; empty iff RootAnchor
	TaskDigest     []byte    `json:"task_digest,omitempty"`   // optional task-envelope digest binding
	Signature      []byte    `json:"signature,omitempty"`     // delegator signature over CanonicalBytes
}

// ErrLinkage is returned when a record's root-anchor marker and parent-digest linkage
// are inconsistent (both set, or neither set).
var ErrLinkage = errors.New("delegation: record must be either root-anchored or parent-linked, not both or neither")

// ErrSignature is returned when a record's delegator signature is missing or does not
// verify against the supplied public key.
var ErrSignature = errors.New("delegation: delegator signature missing or invalid")

// ValidateLinkage enforces that exactly one of the root-anchor marker or the
// parent-record hash is present (card §3.1). A record with both, or neither, is
// dangling and rejected.
func (r Record) ValidateLinkage() error {
	hasParent := len(r.ParentDigest) > 0
	if r.RootAnchor == hasParent {
		// RootAnchor && hasParent  -> both (contradictory)
		// !RootAnchor && !hasParent -> neither (dangling)
		return ErrLinkage
	}
	return nil
}

// CanonicalBytes returns the stable, deterministic serialization of every record
// field EXCEPT the signature (the signature is over these bytes). Authority is
// encoded via its own canonical form, so semantically-equal authority spellings yield
// identical record bytes. The encoding is length-prefixed and fixed-width, so it is
// reproducible across runs, machines, and architectures.
func (r Record) CanonicalBytes(reg *ToolRegistry) ([]byte, error) {
	authBytes, err := CanonicalBytes(r.Authority, reg)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(recordPrefix)
	writeStr(&b, normToken(r.TenantID))
	writeStr(&b, r.DelegatorID)
	writeStr(&b, r.DelegatorKey.ID)
	writeStr(&b, r.DelegatorKey.Algorithm)
	writeStr(&b, r.DelegateID)
	// authority (already canonical)
	writeField(&b, "authority")
	writeU64(&b, uint64(len(authBytes)))
	b.Write(authBytes)
	writeField(&b, "depth_remaining")
	writeU64(&b, uint64(r.DepthRemaining))
	writeField(&b, "validity")
	writeI64(&b, r.Validity.NotBefore)
	writeI64(&b, r.Validity.NotAfter)
	// linkage: a single tagged discriminant so root and parent-linked forms never collide
	writeField(&b, "linkage")
	if r.RootAnchor {
		writeStr(&b, "root")
	} else {
		writeStr(&b, "parent")
		writeBytes(&b, r.ParentDigest)
	}
	writeField(&b, "task_digest")
	writeBytes(&b, r.TaskDigest)
	return b.Bytes(), nil
}

func writeBytes(b *bytes.Buffer, p []byte) {
	writeU64(b, uint64(len(p)))
	b.Write(p)
}

// Digest returns the SHA-256 of the record's canonical bytes (signature excluded),
// routed through the internal/crypto AN-3 boundary. A child record references its
// parent by this digest (ParentDigest).
func (r Record) Digest(reg *ToolRegistry) ([]byte, error) {
	cb, err := r.CanonicalBytes(reg)
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(cb), nil
}

// Sign returns a copy of r with the delegator's signature over its canonical bytes,
// produced through the internal/crypto signer (AN-3). It performs no issuance key
// operation and mints nothing — it only binds the record's own contents to the
// delegator's key (INV-A1 preserved).
func (r Record) Sign(signer crypto.Signer, reg *ToolRegistry) (Record, error) {
	cb, err := r.CanonicalBytes(reg)
	if err != nil {
		return Record{}, err
	}
	sig, err := signer.Sign(cb, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return Record{}, err
	}
	r.Signature = sig
	return r, nil
}

// Verify checks the delegator signature over the record's canonical bytes against
// pub (the delegator public key), through the internal/crypto verify boundary. Any
// tamper to a signed field (including a broadened authority set) invalidates the
// signature. Verify performs no key operation of its own beyond signature checking.
func (r Record) Verify(pub crypto.PublicKey, reg *ToolRegistry) error {
	if len(r.Signature) == 0 {
		return ErrSignature
	}
	cb, err := r.CanonicalBytes(reg)
	if err != nil {
		return err
	}
	if err := crypto.VerifyMessage(pub.DER, cb, r.Signature); err != nil {
		return ErrSignature
	}
	return nil
}
