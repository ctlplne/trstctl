// SPDX-License-Identifier: BUSL-1.1

// Package carriage implements the three interchangeable CARRIAGE forms of an AGID
// credential (AGID-claim-27 / INV-A3 carriage half): an X.509 non-critical certificate
// extension, a workload-identity document, and a signed (JWT-style) token. Each form
// transports the SAME bound values -- the chain-head digest, the agent-stack
// representation (its digest set plus the opaque canonical bytes), and, where present,
// the task-envelope digest -- exactly as the isolated signer bound them in AGID-04.
//
// Carriage is a FAITHFUL TRANSPORT, never an authority (INV-A1): the credential's
// in-signer binding is authoritative and is produced only after verify-before-keygen;
// these encoders merely move the already-bound values onto a credential form, and the
// decoders recover them byte-identically so an AGID-09 relying party re-verifies them
// offline. Encoding is downstream of the signer and can never become a bypass -- nothing
// here decides approval, mints a credential, or performs a key operation on its own.
//
// AN-3 boundary: every HASH and every SIGNATURE routes through internal/crypto. Structural
// encoding (encoding/asn1, encoding/json, encoding/base64) is carriage framing, not a
// crypto primitive, and stays in this package; this package imports no crypto/* directly.
//
// Decoupling: this package deliberately does NOT import internal/agentid/delegation (the gate,
// which pulls the store/database and the signer wiring) nor internal/agentid/agentstack (which
// pulls database/sql via internal/attest). It carries the agent-stack representation as
// OPAQUE CANONICAL BYTES -- exactly as the signer bound them -- so the decode side stays
// lean enough for the AGID-09 relying-party verifier (including its WASM build, which
// cannot link database/sql or net/http). A relying party recovers the prompt/tool/model
// digests by handing the recovered opaque bytes to the agentstack package itself.
package carriage

import (
	"bytes"
	"encoding/binary"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// carriageDomain domain-separates the canonical bytes this package hashes for the
// carriage-integrity digest so it can never collide with a delegation record, an
// authority, an agent-stack, or the AGID-04 binding digest. It intentionally MIRRORS the
// field framing of internal/agentid/delegation.BindingMaterial.CanonicalBytes (same field tags,
// same order, same length-prefixed fixed-width layout) so a value carried here reproduces
// the bound layout deterministically across runs and machines.
const carriageDomain = "agid/agentid/binding/v1"

// BoundValues is the non-secret material the signer bound into the credential in AGID-04,
// carried faithfully by each carriage form. Its fields and their JSON tags are a
// byte-for-byte mirror of internal/agentid/delegation.BindingMaterial: a carriage form encodes
// a BoundValues and decodes back to one that is DeepEqual to the source, so the carried
// digests equal exactly the values AGID-04 bound (AGID-claim-27 / INV-A3).
//
// At least one of ChainHeadDigest / AgentStackDigest is present in a real binding; a
// credential that binds neither is never minted (enforced upstream by the signer). This
// package does not re-enforce that policy -- it transports whatever the signer bound --
// but Validate offers a fail-closed check callers may apply.
type BoundValues struct {
	// ChainHeadDigest is the digest of the verified delegation chain head (empty in the
	// attestation-gated fallback).
	ChainHeadDigest []byte `json:"chain_head_digest,omitempty"`
	// AgentStackDigest is the digest of the agent-stack representation's opaque canonical
	// bytes (the value the signer computed and bound).
	AgentStackDigest []byte `json:"agent_stack_digest,omitempty"`
	// AgentStackRepr is the OPAQUE canonical representation bytes (empty in the chain-only
	// fallback). A relying party recovers the prompt/tool/model digests from these bytes
	// with the agentstack package.
	AgentStackRepr []byte `json:"agent_stack_repr,omitempty"`
	// DesignatedClass is the designated authority class the binding recorded.
	DesignatedClass string `json:"designated_class,omitempty"`
	// AttestationDigest is the attestation-evidence digest (empty when no attestation was
	// required).
	AttestationDigest []byte `json:"attestation_digest,omitempty"`
	// ComparatorVersion pins the exact decision semantics a relying party reproduces.
	ComparatorVersion string `json:"comparator_version"`
	// RootAnchorAuthRef is the root-anchor phishing-resistant auth reference.
	RootAnchorAuthRef string `json:"root_anchor_auth_ref,omitempty"`
	// TaskEnvelopeDigest is the AGID-05 task-envelope digest bound alongside the chain
	// head + agent-stack repr (empty when no record references a task envelope).
	TaskEnvelopeDigest []byte `json:"task_envelope_digest,omitempty"`
}

// Errors returned by the carriage encoders/decoders. All decode paths fail closed: an
// input that cannot be parsed, or that carries no AGID carriage, returns an error rather
// than a partially-populated value.
var (
	// ErrNothingBound is returned by Validate when neither a chain-head digest nor an
	// agent-stack digest is present -- there is no bound subject to carry.
	ErrNothingBound = errors.New("carriage: no bound values (neither chain-head nor agent-stack digest present)")
	// ErrNoAGIDCarriage is returned when a credential form carries no AGID carriage (a
	// certificate without the AGID extension, or a claims document/token without the AGID
	// claim). It lets a relying party distinguish "not an AGID credential" from "malformed
	// AGID credential".
	ErrNoAGIDCarriage = errors.New("carriage: form carries no AGID carriage")
	// ErrMalformedCarriage is returned when an AGID carriage is present but its payload is
	// malformed (bad base64, bad JSON, truncated DER). The decode fails closed.
	ErrMalformedCarriage = errors.New("carriage: malformed AGID carriage payload")
)

// Clone returns a deep copy of bv so a decoded value never aliases the input buffers a
// caller may reuse or mutate.
func (bv BoundValues) Clone() BoundValues {
	return BoundValues{
		ChainHeadDigest:    cloneBytes(bv.ChainHeadDigest),
		AgentStackDigest:   cloneBytes(bv.AgentStackDigest),
		AgentStackRepr:     cloneBytes(bv.AgentStackRepr),
		DesignatedClass:    bv.DesignatedClass,
		AttestationDigest:  cloneBytes(bv.AttestationDigest),
		ComparatorVersion:  bv.ComparatorVersion,
		RootAnchorAuthRef:  bv.RootAnchorAuthRef,
		TaskEnvelopeDigest: cloneBytes(bv.TaskEnvelopeDigest),
	}
}

// Validate fails closed when nothing is bound. Callers that want to reject a carriage
// that transports no subject apply it after decode; the transport itself is agnostic.
func (bv BoundValues) Validate() error {
	if len(bv.ChainHeadDigest) == 0 && len(bv.AgentStackDigest) == 0 {
		return ErrNothingBound
	}
	return nil
}

// CanonicalBytes returns the stable, deterministic byte encoding of the bound values,
// framed IDENTICALLY to internal/agentid/delegation.BindingMaterial.CanonicalBytes (same
// domain tag, same field tags, same order, same length-prefixed fixed-width layout). It
// is the transport-integrity preimage: CarriageDigest is its SHA-256, and a relying party
// that recovers the bound values from any of the three forms recomputes the same bytes.
// Reproducing the bound layout here (rather than importing the gate) keeps the carriage
// package lean while guaranteeing the carried values frame to the exact bytes the signer
// bound.
func (bv BoundValues) CanonicalBytes() []byte {
	var b bytes.Buffer
	b.WriteString(carriageDomain)
	writeField(&b, "chain_head_digest")
	writeBytes(&b, bv.ChainHeadDigest)
	writeField(&b, "agent_stack_digest")
	writeBytes(&b, bv.AgentStackDigest)
	writeField(&b, "agent_stack_repr")
	writeBytes(&b, bv.AgentStackRepr)
	writeField(&b, "designated_class")
	writeStr(&b, bv.DesignatedClass)
	writeField(&b, "attestation_digest")
	writeBytes(&b, bv.AttestationDigest)
	writeField(&b, "comparator_version")
	writeStr(&b, bv.ComparatorVersion)
	writeField(&b, "root_anchor_auth_ref")
	writeStr(&b, bv.RootAnchorAuthRef)
	writeField(&b, "task_envelope_digest")
	writeBytes(&b, bv.TaskEnvelopeDigest)
	return b.Bytes()
}

// CarriageDigest returns the SHA-256 of the canonical bytes, through internal/crypto
// (AN-3). It is the value a carrier may stamp for integrity and a relying party
// recomputes to confirm the three forms transported identical bound values.
func (bv BoundValues) CarriageDigest() []byte {
	return crypto.SHA256Sum(bv.CanonicalBytes())
}

// Decoder is the COMMON decode surface every carriage form satisfies, so a single
// relying-party path (AGID-09) reads an X.509 extension, a workload-identity document,
// and a signed token identically: hand it the form's bytes, receive the bound values.
// Implementations fail closed (ErrNoAGIDCarriage / ErrMalformedCarriage) and never panic
// on untrusted input.
type Decoder interface {
	// Decode recovers the bound values from one carriage form's serialized bytes.
	Decode(form []byte) (BoundValues, error)
	// Kind names the form for diagnostics ("x509", "workload-identity", "signed-token").
	Kind() string
}

// Decoders returns the three built-in decoders, one per carriage form, so a relying party
// can select by kind or try each. Every element reads the SAME bound values a matching
// encoder wrote.
func Decoders() []Decoder {
	return []Decoder{X509Decoder{}, WorkloadDocDecoder{}, TokenDecoder{}}
}

// ---- deterministic framing helpers (mirror internal/agentid/delegation) ----

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

func cloneBytes(p []byte) []byte {
	if len(p) == 0 {
		return nil
	}
	return append([]byte(nil), p...)
}
