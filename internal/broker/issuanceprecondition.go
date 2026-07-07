// SPDX-License-Identifier: MPL-2.0

package broker

import (
	"context"
	"errors"
)

// issuanceprecondition.go is the broker's generic, feature-neutral issuance-
// precondition seam. It is the control-plane analogue of the AN-4 signer's
// signing.WithIssuanceGate seam: the core defines ONLY this generic extension point;
// what a precondition actually verifies, and how a decision is reached, lives entirely
// in an edition implementation attached via WithIssuancePrecondition. The core-only
// build attaches none and the seam is inert.
//
// The seam names nothing edition-specific. It takes a generic IssuanceView (a
// read-only projection of the already-public IssueRequest) and returns a plain error:
// nil approves, non-nil refuses. It exists so an external precondition can be consulted
// on a CHAIN-BOUND issuance path (Broker.IssueChainBound) without the core knowing what
// that precondition means.
//
// Zero-removal guarantee (INV-A10): this seam does NOT touch the free single-hop
// attested-ephemeral badge. Broker.Issue is unchanged and never consults a precondition;
// the hook engages ONLY on the explicit chain-bound path, and only when attached. An
// unlicensed / core-only deployment attaches nothing, so the seam is dormant and the
// free badge issues exactly as before.

// IssuanceView is the generic, read-only projection of an issuance request handed to an
// attached precondition. It carries only fields the request already exposes and names
// nothing edition-specific: the core neither adds nor interprets any semantics here. An
// edition precondition reads this view (and whatever out-of-band context it holds) to
// reach its own decision.
type IssuanceView struct {
	// TenantID scopes the request to a tenant (AN-1).
	TenantID string
	// AgentID is the requested agent identity's identifier.
	AgentID string
	// Scopes are the requested scopes, copied defensively.
	Scopes []string
	// AttestationMethod names the attestation method presented with the request.
	AttestationMethod string
	// IdempotencyKey is the request's idempotency key (AN-5).
	IdempotencyKey string
}

// IssuancePrecondition is a generic precondition consulted before a chain-bound
// issuance mints. It returns nil to approve and a non-nil error to refuse; a refusal
// fails the chain-bound issuance closed with NO mint. The contract names nothing
// edition-specific: the core forwards a generic view and enforces only the ordering
// (precondition first, mint only on approval).
type IssuancePrecondition interface {
	CheckIssuancePrecondition(ctx context.Context, view IssuanceView) error
}

// IssuancePreconditionFunc adapts a bare function to IssuancePrecondition, so an
// attach seam may supply a closure directly.
type IssuancePreconditionFunc func(ctx context.Context, view IssuanceView) error

// CheckIssuancePrecondition implements IssuancePrecondition.
func (f IssuancePreconditionFunc) CheckIssuancePrecondition(ctx context.Context, view IssuanceView) error {
	return f(ctx, view)
}

// BrokerOption configures a Broker at construction beside its Config. It is the
// broker's extension seam; today the only option is WithIssuancePrecondition.
type BrokerOption func(*Broker)

// WithIssuancePrecondition attaches a generic issuance precondition consulted on the
// chain-bound issuance path (Broker.IssueChainBound). A nil precondition is ignored, so
// an unlicensed attach leaves the seam inert. This is the broker analogue of
// signing.WithIssuanceGate: the core names only the generic seam; the edition supplies
// the implementation without importing ee/ into core.
func WithIssuancePrecondition(p IssuancePrecondition) BrokerOption {
	return func(b *Broker) {
		if p != nil {
			b.issuancePrecondition = p
		}
	}
}

// ErrNoIssuancePrecondition is returned when Broker.IssueChainBound is called but no
// issuance precondition is attached (core-only / unlicensed build). The chain-bound
// path fails closed with this error and mints nothing, mirroring
// signing.ErrNoIssuanceGate. The free single-hop Broker.Issue path is unaffected.
var ErrNoIssuancePrecondition = errors.New("broker: no issuance precondition attached")

// viewFor builds the generic IssuanceView forwarded to an attached precondition. It
// exposes only already-public request fields and copies the scope slice defensively so
// the precondition cannot mutate caller state.
func (b *Broker) viewFor(req IssueRequest) IssuanceView {
	return IssuanceView{
		TenantID:          b.cfg.TenantID,
		AgentID:           req.AgentID,
		Scopes:            append([]string(nil), req.Scopes...),
		AttestationMethod: req.Method,
		IdempotencyKey:    req.IdempotencyKey,
	}
}

// IssueChainBound is the chain-bound issuance path: it consults the attached issuance
// precondition BEFORE any credential is minted, and mints ONLY when the precondition
// approves (returns nil). It fails closed when no precondition is attached
// (ErrNoIssuancePrecondition, the core-only / unlicensed state) and when the
// precondition refuses (returning its error), performing NO mint in either case.
//
// On approval it hands off to the unchanged single-hop Issue, so the chain-bound path
// is a strict superset — precondition first, then the identical attested issuance. This
// is what keeps the free single-hop badge byte-for-byte intact (INV-A10): Issue itself
// is never modified and never consults the precondition; only this explicit path does.
// The attaching edition supplies the real precondition through WithIssuancePrecondition;
// the core proves only the ordering here and names nothing edition-specific.
func (b *Broker) IssueChainBound(ctx context.Context, req IssueRequest) (AgentIdentity, error) {
	if req.AgentID == "" {
		return AgentIdentity{}, errors.New("broker: AgentID required")
	}
	p := b.issuancePrecondition
	if p == nil {
		return AgentIdentity{}, ErrNoIssuancePrecondition
	}
	if err := p.CheckIssuancePrecondition(ctx, b.viewFor(req)); err != nil {
		return AgentIdentity{}, err
	}
	return b.Issue(ctx, req)
}
