// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package taskenv defines the AGID task-envelope model (patent claim 2 / INV-A4): the
// signed statement of a task's intent, its input commitments, its expiry, and the
// requester's identity + signature over a canonical serialization. A delegation record
// may reference a task envelope by its canonical digest (record.TaskDigest, AGID-01);
// the isolated signer verifies the referenced envelope's signature and expiry as a
// PRECONDITION of the key operation (AGID-04's gate, extended by this card), and binds
// the envelope digest into the issued credential ALONGSIDE the chain-head digest and the
// agent-stack representation (INV-A3 is additive, not replaced).
//
// This package holds NO issuance key and mints nothing: it models the envelope, computes
// a byte-stable canonical digest, and verifies a requester signature + non-expiry. All
// hashing and signature verification route through the core internal/crypto AN-3
// boundary; no crypto/* is imported here (AN-3). Like ee/agentid/delegation, this is
// proprietary Enterprise/Provider material behind the ee/ fence; core never imports it,
// and it imports nothing that would drag a datastore into the isolated signer (AN-4): it
// depends only on internal/crypto.
//
// The canonical serialization mirrors the length-prefixed, fixed-endian, sorted-set
// discipline of ee/agentid/delegation/authority.go and record.go, so the envelope digest
// is reproducible across runs, machines, and architectures (acceptance criterion 3).
package taskenv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"

	"trstctl.com/trstctl/internal/crypto"
)

// envelopePrefix domain-separates the canonical task-envelope encoding from every other
// hashed structure in the repo (a delegation record, an authority, an agent-stack
// representation, a binding). It is part of the v1 canonical semantics.
const envelopePrefix = "agid/taskenv/envelope/v1"

// KeyRef references the requester's signing key without carrying key material. ID is an
// opaque, tenant-scoped key identifier the signer resolves to a public key via its trust
// lookup; Algorithm names the signature algorithm. No private (or public) key bytes live
// here (AN-8): verification takes the public key DER out of band (VerifySignatureAndExpiry
// resolves it through the caller-supplied trust lookup).
type KeyRef struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
}

// Commitment is an input commitment: a named binding to a digest of a specific input the
// task is authorized over (a document, a dataset, a parameter blob). Name is the input's
// role; Digest is an opaque digest of that input's bytes (computed by the requester;
// this package binds it verbatim, it does not recompute it). Commitments let a relying
// party (AGID-09) confirm the agent acted only on the exact inputs the requester
// committed to.
type Commitment struct {
	Name   string `json:"name"`
	Digest []byte `json:"digest"`
}

// TaskIntent states WHAT the task is: either a structured Description, an explicit
// IntentDigest (a digest of an out-of-band task specification), or both, plus the set of
// input commitments. At least one of Description / IntentDigest is required (Validate);
// an envelope that states no intent is refused fail-closed. Both are bound into the
// canonical bytes, so a change to either flips the envelope digest.
type TaskIntent struct {
	// Description is a structured, human-meaningful task description (optional if
	// IntentDigest is set). Bound verbatim.
	Description string `json:"description,omitempty"`
	// IntentDigest is a digest of an out-of-band task specification (optional if
	// Description is set). Bound verbatim.
	IntentDigest []byte `json:"intent_digest,omitempty"`
	// InputCommitments are the named input digests the task is authorized over. Bound in
	// a canonical (sorted) order so ordering is not semantically significant.
	InputCommitments []Commitment `json:"input_commitments,omitempty"`
}

// Window is a validity window as inclusive Unix-second bounds, matching the delegation
// Window semantics: a zero-valued window (NotBefore == 0 && NotAfter == 0) means "no
// bound" (always valid); a set NotBefore/NotAfter is honored strictly. Expiry is the
// task envelope's own lifetime, verified against the issuance time inside the signer.
type Window struct {
	NotBefore int64 `json:"not_before"`
	NotAfter  int64 `json:"not_after"`
}

// Envelope is the signed task envelope (claim 2): the requester's identity + key
// reference, the task intent (structured and/or digest) with its input commitments, the
// expiry window, and the requester's signature over the canonical serialization of the
// preceding fields. The signer verifies Signature (against the requester key resolved
// out of band) and Expiry BEFORE the key operation; on success the credential binds
// Digest().
//
// This structure carries no issuance key and mints nothing: Sign only attests the
// envelope's own contents with the requester's key (INV-A1 preserved by construction).
type Envelope struct {
	RequesterID  string     `json:"requester_id"`
	RequesterKey KeyRef     `json:"requester_key"`
	Task         TaskIntent `json:"task"`
	Expiry       Window     `json:"expiry"`
	Signature    []byte     `json:"signature,omitempty"` // requester signature over CanonicalBytes
}

// Envelope errors.
var (
	// ErrNoIntent is returned when an envelope states no task intent at all (neither a
	// description nor an explicit intent digest). Fail-closed: the signer refuses it.
	ErrNoIntent = errors.New("taskenv: envelope states no task intent (needs a description or an intent digest)")
	// ErrSignature is returned when an envelope's requester signature is missing or does
	// not verify against the supplied public key.
	ErrSignature = errors.New("taskenv: requester signature missing or invalid")
	// ErrExpired is returned when the issuance time falls outside the envelope's expiry
	// window (expired, or not yet valid).
	ErrExpired = errors.New("taskenv: task envelope is expired or not yet valid")
	// ErrUnknownRequester is returned when the requester key id does not resolve through
	// the signer's trust lookup. Fail-closed: an unresolved requester cannot be trusted.
	ErrUnknownRequester = errors.New("taskenv: requester key id does not resolve to a trusted key")
)

// Validate checks the envelope is well-formed enough to bind: it must state some intent.
// It does NOT check the signature or expiry (that is VerifySignatureAndExpiry). It is
// fail-closed: the signer refuses an envelope that does not validate.
func (e Envelope) Validate() error {
	if len(e.Task.Description) == 0 && len(e.Task.IntentDigest) == 0 {
		return ErrNoIntent
	}
	return nil
}

// canonicalCommitments returns the input commitments in canonical order: sorted by
// (Name, Digest) so a differently-ordered but equal commitment set yields identical
// bytes. It copies rather than mutating the caller's slice.
func canonicalCommitments(cs []Commitment) []Commitment {
	out := make([]Commitment, len(cs))
	copy(out, cs)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return bytes.Compare(out[i].Digest, out[j].Digest) < 0
	})
	return out
}

// CanonicalBytes returns the stable, deterministic serialization of every envelope field
// EXCEPT the signature (the signature is over these bytes). Sets are canonically ordered;
// the encoding is length-prefixed and fixed-width (big-endian), so it is reproducible
// across runs, machines, and architectures (mirrors delegation/record.go
// CanonicalBytes).
func (e Envelope) CanonicalBytes() []byte {
	var b bytes.Buffer
	b.WriteString(envelopePrefix)
	writeStr(&b, e.RequesterID)
	writeStr(&b, e.RequesterKey.ID)
	writeStr(&b, e.RequesterKey.Algorithm)
	// task intent
	writeField(&b, "description")
	writeStr(&b, e.Task.Description)
	writeField(&b, "intent_digest")
	writeBytes(&b, e.Task.IntentDigest)
	// input commitments (canonically ordered)
	cs := canonicalCommitments(e.Task.InputCommitments)
	writeField(&b, "input_commitments")
	writeU64(&b, uint64(len(cs)))
	for _, c := range cs {
		writeStr(&b, c.Name)
		writeBytes(&b, c.Digest)
	}
	// expiry
	writeField(&b, "expiry")
	writeI64(&b, e.Expiry.NotBefore)
	writeI64(&b, e.Expiry.NotAfter)
	return b.Bytes()
}

// Digest returns the SHA-256 of the envelope's canonical bytes (signature excluded),
// routed through the internal/crypto AN-3 boundary. This is the canonical, byte-stable
// envelope digest a delegation record references (record.TaskDigest) and the value bound
// into the credential (acceptance criteria 2/3).
func (e Envelope) Digest() ([]byte, error) {
	return crypto.SHA256Sum(e.CanonicalBytes()), nil
}

// Sign returns a copy of e with the requester's signature over its canonical bytes,
// produced through the internal/crypto signer (AN-3). It performs no issuance key
// operation and mints nothing -- it only binds the envelope's own contents to the
// requester's key.
func (e Envelope) Sign(signer crypto.Signer) (Envelope, error) {
	sig, err := signer.Sign(e.CanonicalBytes(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return Envelope{}, err
	}
	e.Signature = sig
	return e, nil
}

// VerifySignature checks the requester signature over the envelope's canonical bytes
// against pub (the requester public key), through the internal/crypto verify boundary
// (AN-3). Any tamper to a signed field invalidates the signature. It performs no key
// operation of its own beyond signature checking. A missing signature fails closed.
func (e Envelope) VerifySignature(pub crypto.PublicKey) error {
	if len(e.Signature) == 0 {
		return ErrSignature
	}
	if err := crypto.VerifyMessage(pub.DER, e.CanonicalBytes(), e.Signature); err != nil {
		return ErrSignature
	}
	return nil
}

// ---- canonical writer helpers (length-prefixed, fixed big-endian; mirrors the
// delegation package's private writers so the two encodings share their discipline). ----

func writeField(b *bytes.Buffer, name string) { writeStr(b, name) }

func writeStr(b *bytes.Buffer, s string) {
	writeU64(b, uint64(len(s)))
	b.WriteString(s)
}

func writeBytes(b *bytes.Buffer, p []byte) {
	writeU64(b, uint64(len(p)))
	b.Write(p)
}

func writeU64(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}

func writeI64(b *bytes.Buffer, v int64) { writeU64(b, uint64(v)) }
