// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"encoding/json"
	"fmt"
)

// wire.go defines the edition-private decode of the opaque bodies the core AGID-04a
// seam forwards (signing.IssuancePreconditions.{Preconditions,SubjectRepr,Attestation}).
// The core never parses these bytes; the gate does, here, fail-closed. A malformed
// body is a decode error that the gate turns into a signed refusal with NO key op
// (INV-A1): an attacker who ships garbage over the seam gets a refusal, never a
// credential.
//
// The three bodies are:
//   - Preconditions: the self-describing delegation chain (each RecordEnvelope
//     carries its delegator public key DER + the signed Record) plus the designated
//     authority class the chain head claims (for the min-attestation-class gate).
//   - SubjectRepr: the agent-stack representation to bind (AGID-03). Optional in the
//     chain-only fallback (AGID-claim-31).
//   - Attestation: the attestation evidence body (type + blob). Optional in the
//     chain-only fallback; REQUIRED when a designated authority class demands a
//     minimum attestation class (AGID-claim-10) and in the attestation-gated fallback
//     (AGID-claim-32).
//
// Decoding is JSON: deterministic, self-delimiting, and the same encoding the AGID-02
// ledger events use. The gate treats every field as untrusted input and re-verifies
// everything cryptographically; JSON is a carriage format only, never a trust
// boundary.

// RecordEnvelope is one hop of the self-describing chain the caller ships over the
// seam: the signed delegation Record plus the DER of the delegator public key that
// signed it. The gate verifies each hop's signature with the CARRIED public key and
// then verifies that public key chains to a root anchor the signer holds (a caller
// cannot self-certify by simply attaching a key of their choosing: the root-anchor
// check is what makes the carried key trustworthy). No private key material is ever
// carried -- DER is a public SubjectPublicKeyInfo only (AN-8).
type RecordEnvelope struct {
	// Record is the signed delegation record for this hop (record.go). Its Signature
	// field must verify against DelegatorPublicDER.
	Record Record `json:"record"`
	// DelegatorPublicDER is the PKIX/DER SubjectPublicKeyInfo of the delegator key
	// that signed Record. Public material only.
	DelegatorPublicDER []byte `json:"delegator_public_der"`
}

// PreconditionsBody is the decoded delegation-precondition body carried opaquely in
// signing.IssuancePreconditions.Preconditions. Chain is ordered ROOT-FIRST (the
// root-anchored hop is Chain[0]); the head is the last element. DesignatedClass, when
// non-empty, names the authority class the chain head is designated as, which the
// min-attestation-class policy gates (AGID-claim-10).
type PreconditionsBody struct {
	// Chain is the delegation chain, ordered root-first. Empty in the
	// attestation-gated fallback (AGID-claim-32), where an agent-stack representation +
	// verified attestation stands alone with no multi-hop chain.
	Chain []RecordEnvelope `json:"chain,omitempty"`
	// DesignatedClass names the authority class the head is designated as, keying the
	// min-attestation-class policy (AGID-claim-10). Empty means no class gate applies.
	DesignatedClass string `json:"designated_class,omitempty"`
	// Envelope carries the encoded task envelope (ee/agentid/taskenv) the chain head
	// references via its Record.TaskDigest (AGID-05, AGID-claim-2). Optional: present only
	// when a record references a task envelope. The gate verifies its signature + expiry
	// as a precondition of the key op and binds its digest into the credential; when
	// absent and no record references an envelope, the gate behaves exactly as AGID-04b.
	Envelope []byte `json:"envelope,omitempty"`
	// ReachabilityVerdict carries the encoded signed reachability verdict (ee/agentid/reach)
	// the reachability engine produced OUTSIDE the signer (AGID-06, AGID-claims-5/6 / INV-A5).
	// Optional in carriage, but fail-closed in effect: the gate verifies the verdict's
	// signature + watermark + ceiling determination as a PRECONDITION of the key op, bound
	// to the FINAL record's authority. When the gate has reachability enforcement enabled
	// (Config.ReachabilityTrust set or Config.RequireReachability) and a chain is present,
	// an ABSENT/unsigned/tampered/stale/Exceeded verdict is treated as a ceiling violation
	// (no key op). When reachability is not enabled, this is inert and the gate behaves
	// exactly as AGID-05 (no regression).
	ReachabilityVerdict []byte `json:"reachability_verdict,omitempty"`
}

// ErrDecodePreconditions is returned when the opaque precondition body cannot be
// decoded. The gate maps it to a fail-closed refusal (no key op).
var ErrDecodePreconditions = fmt.Errorf("delegation: cannot decode issuance preconditions body")

// decodePreconditions decodes the opaque precondition body fail-closed. An empty body
// is a valid (chain-less) body only for the attestation-gated fallback; the caller's
// downstream verification decides whether that is acceptable, not this decoder.
func decodePreconditions(b []byte) (PreconditionsBody, error) {
	if len(b) == 0 {
		return PreconditionsBody{}, nil
	}
	var body PreconditionsBody
	if err := json.Unmarshal(b, &body); err != nil {
		return PreconditionsBody{}, fmt.Errorf("%w: %v", ErrDecodePreconditions, err)
	}
	return body, nil
}

// EncodePreconditionsBody encodes a precondition body to the opaque JSON carriage the
// AGID-04a seam forwards (signing.IssuancePreconditions.Preconditions). It is the
// control-plane inverse of decodePreconditions: the AGID-07b broker precondition (in the
// control-plane brokerstore package) uses it to hand the resolved chain to the AGID-04
// gate over the same seam the in-process signer path uses, so the broker's consult and the
// signer's own gatedIssue verify byte-identical bodies. It is EXPORTED because the
// precondition lives in a separate package (brokerstore, kept out of the signer's
// datastore-free closure). An empty chain, class, envelope, and verdict yield a nil body,
// matching decodePreconditions' empty-body handling (a nil body decodes to the zero body).
func EncodePreconditionsBody(body PreconditionsBody) ([]byte, error) {
	if len(body.Chain) == 0 && body.DesignatedClass == "" &&
		len(body.Envelope) == 0 && len(body.ReachabilityVerdict) == 0 {
		return nil, nil
	}
	return json.Marshal(body)
}
