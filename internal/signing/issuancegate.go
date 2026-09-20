// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
)

// IssuanceGate is a generic issuance-precondition extension attached to the AN-4
// signer. The core defines only this generic seam; the concrete precondition
// semantics -- what the opaque bodies mean and how a decision is reached -- live in
// an edition implementation attached via WithIssuanceGate. The core-only build
// attaches none and the gated issuance path is inert.
//
// The interface names nothing edition-specific: it takes a generic
// IssuancePreconditions request whose bodies are opaque to core and returns a
// generic IssuanceDecision whose bodies are likewise opaque. It mirrors the
// SuccessionMinter seam precisely.
//
// The single ordering guarantee the core makes is INV-A1: the gate is consulted
// BEFORE any keystore key operation, and a key op proceeds only when the gate
// returns an approving decision. A gate that returns an error, or a decision that
// is not Approved, fails the issuance closed with no key op performed. Refusal
// detail the edition wishes to surface travels in the opaque
// IssuanceDecision.RefusalRecord.
type IssuanceGate interface {
	VerifyIssuancePreconditions(ctx context.Context, req IssuancePreconditions) (IssuanceDecision, error)
}

// IssuancePreconditions is the generic issuance-precondition request. It carries NO
// private key material and no edition-specific structure: the asserted context is a
// tenant id, an opaque asserted trust-anchor reference, validity bounds, and three
// opaque bodies whose meaning is defined entirely by the attached edition gate. The
// core never parses these bodies; it forwards them and enforces only the
// consult-before-keyop ordering.
type IssuancePreconditions struct {
	// TenantID scopes the request to a tenant (AN-1). Opaque to the gate contract:
	// core neither validates nor interprets it here.
	TenantID string

	// TrustAnchorRef is the asserted trust-anchor reference the caller claims this
	// issuance derives from. It is an opaque handle/identifier; the edition gate
	// resolves and checks it. Core does not interpret it.
	TrustAnchorRef string

	// NotBefore and NotAfter are the asserted validity bounds (Unix seconds) for the
	// credential to be issued. Generic scalars; the gate decides whether they are
	// acceptable.
	NotBefore int64
	NotAfter  int64

	// Preconditions is the opaque precondition body: the serialized set of
	// conditions the edition gate must verify before issuance. Opaque to core.
	Preconditions []byte

	// SubjectRepr is the opaque representation of the subject state to be bound into
	// the issued credential. Opaque to core: it is forwarded to the gate and, on an
	// approved decision, its binding is reflected in IssuanceDecision.BindingMaterial.
	SubjectRepr []byte

	// Attestation is the opaque attestation evidence accompanying the request.
	// AttestationMethod names the method that produced it. Both are opaque to core;
	// the gate decides how (or whether) to consume them.
	Attestation       []byte
	AttestationMethod string
}

// IssuanceDecision is the generic issuance-precondition decision. It carries only
// non-secret material: an approval flag and opaque bodies the edition gate
// produces. The core reads only Approved to enforce ordering; every other field is
// opaque and forwarded unaltered.
type IssuanceDecision struct {
	// Approved gates the key op: only when true may the issuance path proceed to a
	// keystore key operation (INV-A1). False (or an error from the gate) fails the
	// issuance closed with no key op.
	Approved bool

	// RefusalRecord is the opaque refusal artifact the edition gate produces when it
	// does not approve (for example a signed refusal). Opaque to core; surfaced to
	// the caller/recorded unaltered.
	RefusalRecord []byte

	// BindingMaterial is the opaque material the gate wants bound into the issued
	// credential (for example a binding digest/commitment). Opaque to core.
	BindingMaterial []byte

	// CredentialPublicDER is the DER-encoded public key of the issued credential when
	// the gate itself produced or selected it. Opaque to core; public material only.
	CredentialPublicDER []byte

	// EncodedRecord is the opaque encoded issuance record the gate produced. Opaque
	// to core.
	EncodedRecord []byte
}

// ErrNoIssuanceGate is returned when no issuance gate is attached (core-only
// build). The gated issuance path fails closed with this error, mirroring
// ErrNoMinter.
var ErrNoIssuanceGate = errors.New("signing: no issuance gate attached")

// WithIssuanceGate attaches an issuance gate to the signer, beside
// WithSuccessionMinter and WithKeyFactory. The core names only the generic seam;
// the edition supplies the implementation without importing ee/ into core.
func WithIssuanceGate(g IssuanceGate) ServerOption {
	return func(s *Server) {
		if g != nil {
			s.issuanceGate = g
		}
	}
}

// verifyIssuancePreconditions dispatches to the attached issuance gate, failing
// closed when none is attached. It is the in-process consult point that gatedIssue
// calls before any key op, so the same precondition discipline applies whether
// issuance is driven in-process or (once AGID-INT-WIRE lands the RPC) over the
// transport. It performs NO key op itself: it only consults the gate.
func (s *Server) verifyIssuancePreconditions(ctx context.Context, req IssuancePreconditions) (IssuanceDecision, error) {
	s.mu.Lock()
	g := s.issuanceGate
	s.mu.Unlock()
	if g == nil {
		return IssuanceDecision{}, ErrNoIssuanceGate
	}
	return g.VerifyIssuancePreconditions(ctx, req)
}

// gatedIssue is the generic issuance path that enforces INV-A1: the issuance gate
// is consulted BEFORE any keystore key operation, and the supplied key op runs only
// when the gate returns an Approved decision. It fails closed when no gate is
// attached (ErrNoIssuanceGate, core-only build), and when the gate errors or
// refuses it returns the decision and performs NO key op.
//
// The core intentionally keeps the orchestration minimal: keyOp is an opaque
// closure the caller supplies (in production, the edition's issuance wiring), and
// the core guarantees only the ordering -- gate first, key op only on approval.
// AGID-04b fills in the real key-op/binding orchestration behind this seam; the
// core proves the ordering with an instrumented keystore.
func (s *Server) gatedIssue(ctx context.Context, req IssuancePreconditions, keyOp func(context.Context, IssuanceDecision) error) (IssuanceDecision, error) {
	decision, err := s.verifyIssuancePreconditions(ctx, req)
	if err != nil {
		return IssuanceDecision{}, err
	}
	if !decision.Approved {
		// Refused: no key op runs. The opaque refusal record (if any) travels back to
		// the caller unaltered.
		return decision, nil
	}
	if keyOp != nil {
		if err := keyOp(ctx, decision); err != nil {
			return decision, err
		}
	}
	return decision, nil
}
