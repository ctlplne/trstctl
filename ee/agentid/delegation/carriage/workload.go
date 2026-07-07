// SPDX-License-Identifier: LicenseRef-trstctl-EE

package carriage

import (
	"encoding/json"
	"errors"
)

// workload.go is the workload-identity-document carriage form (claim 27, second
// alternative): the bound values ride as CLAIMS in a JSON workload-identity document. The
// document nests the AGID binding under a single reserved claim (agidBindingClaim) so it
// coexists with the issuer's own workload-identity claims (subject, audience, issuer,
// validity) without colliding; a relying party reads that one claim to recover the bound
// values and re-verify them offline (AGID-09).
//
// AN-3: no crypto primitive here -- a workload-identity document's own signature/wrapping
// is applied by the issuer's existing workload-identity path (consumed read-only); this
// file only encodes/decodes the AGID binding CLAIM structure. Digest byte-slices are
// carried as base64url strings (the JSON convention for binary claim values); the shared
// bindingClaim marshals them so all three claim-bearing forms carry byte-identical values.

// agidBindingClaim is the reserved claim name under which the AGID binding rides in a
// workload-identity document (and, identically, in the signed token). A private,
// namespaced claim name keeps the binding from colliding with standard workload-identity
// or JWT claims.
const agidBindingClaim = "agid_binding"

// ErrNoBindingClaim is returned when a claims document carries no AGID binding claim.
var ErrNoBindingClaim = errors.New("carriage: document carries no AGID binding claim")

// bindingClaim is the on-the-wire JSON shape of the AGID binding claim, shared by the
// workload-identity document and the signed token so both carry byte-identical values.
// Digests are base64url (via byteString); strings are carried verbatim. The field set and
// omitempty rules mirror BoundValues so an absent bound field (e.g. an envelope-free
// binding's empty task-envelope digest) round-trips to an absent field, not a present
// empty one.
type bindingClaim struct {
	ChainHeadDigest    byteString `json:"chain_head_digest,omitempty"`
	AgentStackDigest   byteString `json:"agent_stack_digest,omitempty"`
	AgentStackRepr     byteString `json:"agent_stack_repr,omitempty"`
	DesignatedClass    string     `json:"designated_class,omitempty"`
	AttestationDigest  byteString `json:"attestation_digest,omitempty"`
	ComparatorVersion  string     `json:"comparator_version"`
	RootAnchorAuthRef  string     `json:"root_anchor_auth_ref,omitempty"`
	TaskEnvelopeDigest byteString `json:"task_envelope_digest,omitempty"`
}

// bindingClaimOf projects bound values into the wire claim shape.
func bindingClaimOf(bv BoundValues) bindingClaim {
	return bindingClaim{
		ChainHeadDigest:    byteString(bv.ChainHeadDigest),
		AgentStackDigest:   byteString(bv.AgentStackDigest),
		AgentStackRepr:     byteString(bv.AgentStackRepr),
		DesignatedClass:    bv.DesignatedClass,
		AttestationDigest:  byteString(bv.AttestationDigest),
		ComparatorVersion:  bv.ComparatorVersion,
		RootAnchorAuthRef:  bv.RootAnchorAuthRef,
		TaskEnvelopeDigest: byteString(bv.TaskEnvelopeDigest),
	}
}

// boundValues reconstructs bound values from the wire claim shape. Every digest is cloned
// out of the decoded buffer so the result never aliases the input.
func (c bindingClaim) boundValues() BoundValues {
	return BoundValues{
		ChainHeadDigest:    cloneBytes(c.ChainHeadDigest),
		AgentStackDigest:   cloneBytes(c.AgentStackDigest),
		AgentStackRepr:     cloneBytes(c.AgentStackRepr),
		DesignatedClass:    c.DesignatedClass,
		AttestationDigest:  cloneBytes(c.AttestationDigest),
		ComparatorVersion:  c.ComparatorVersion,
		RootAnchorAuthRef:  c.RootAnchorAuthRef,
		TaskEnvelopeDigest: cloneBytes(c.TaskEnvelopeDigest),
	}
}

// WorkloadDocument is a minimal workload-identity document carrying the AGID binding
// claim alongside the issuer's standard claims. The standard claims are optional here
// (the issuer's existing workload-identity path owns them); this type exists so the
// carriage encoder produces a self-contained document a relying party can decode and so
// tests exercise the exact claim placement. Extra claims a real issuer adds are ignored on
// decode (the AGID binding claim is read by name), so this form composes with a richer
// issuer document.
type WorkloadDocument struct {
	Subject  string       `json:"sub,omitempty"`
	Audience string       `json:"aud,omitempty"`
	Issuer   string       `json:"iss,omitempty"`
	Binding  bindingClaim `json:"agid_binding"`
}

// EncodeWorkloadDoc encodes bv as the AGID binding claim inside a workload-identity
// document and returns the document JSON. subject/audience/issuer are the issuer-supplied
// standard claims (any may be empty); they are carried for completeness but are not part
// of the binding a relying party re-verifies.
func EncodeWorkloadDoc(bv BoundValues, subject, audience, issuer string) ([]byte, error) {
	doc := WorkloadDocument{
		Subject:  subject,
		Audience: audience,
		Issuer:   issuer,
		Binding:  bindingClaimOf(bv),
	}
	return json.Marshal(doc)
}

// DecodeWorkloadDoc recovers the bound values from a workload-identity document's JSON. It
// reads the AGID binding claim by name (so it also decodes a richer issuer document that
// carries extra claims) and fails closed on malformed JSON or a missing binding claim. It
// never panics on untrusted input. It is the entry point the AGID-09 relying-party
// workload-identity path uses.
func DecodeWorkloadDoc(docJSON []byte) (BoundValues, error) {
	// Decode into a map first so we can distinguish "no agid_binding claim" from "present
	// but malformed", and tolerate arbitrary sibling claims a real issuer adds.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(docJSON, &envelope); err != nil {
		return BoundValues{}, ErrMalformedCarriage
	}
	raw, ok := envelope[agidBindingClaim]
	if !ok {
		return BoundValues{}, ErrNoBindingClaim
	}
	var claim bindingClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		return BoundValues{}, ErrMalformedCarriage
	}
	return claim.boundValues(), nil
}

// WorkloadDocDecoder adapts the workload-identity document form to the common Decoder
// surface: its Decode takes the document JSON bytes.
type WorkloadDocDecoder struct{}

// Decode implements Decoder for a workload-identity document.
func (WorkloadDocDecoder) Decode(docJSON []byte) (BoundValues, error) {
	return DecodeWorkloadDoc(docJSON)
}

// Kind implements Decoder.
func (WorkloadDocDecoder) Kind() string { return "workload-identity" }
