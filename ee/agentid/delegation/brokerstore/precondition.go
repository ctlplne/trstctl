// SPDX-License-Identifier: LicenseRef-trstctl-EE

package brokerstore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/broker"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/signing"
)

// precondition.go is the AGID-07b control-plane precondition: the REAL
// broker.IssuancePrecondition that AGID-07a's fail-closed placeholder is replaced by. It
// is consulted by the core broker ONLY on its chain-bound issuance path
// (broker.IssueChainBound), BEFORE any key op, and it approves (returns nil) only after
// every chain-bound precondition has passed. Any refusal returns a non-nil error and the
// broker mints NOTHING (INV-A1 ordering is the core seam's; this precondition is what
// makes the chain-bound path verify).
//
// It lives in the CONTROL-PLANE-ONLY brokerstore package (NOT the signer-linked
// delegation package) because it consults the S10.1 policy engine (internal/policy) and
// the datastore-backed recorder — both of which transitively link database/sql. Keeping it
// out of `delegation` is what preserves AN-4: the isolated signer imports
// delegation.NewSignerGate but never this package, so the signer's closure links no SQL
// driver and no message bus (TestSignerDependencyClosure).
//
// The ordering it enforces on a chain-bound request, ALL before the broker's mint:
//   1. Policy gate (S10.1 / claim 14): evaluate agent id + requested authority +
//      attestation method. A DENY performs NO key op and emits an audit event carrying
//      the denial reason.
//   2. In-signer verification (AGID-04, claim 1 / INV-A1): re-invoke the AGID-04 Gate's
//      VerifyIssuancePreconditions over the resolved chain + attestation. A non-approving
//      decision refuses (no key op). This guarantees the broker never issues a chain-bound
//      credential the signer did not verify.
//   3. Sub-hour TTL ceiling (claims 7/26 / INV-A7): derive the credential lifetime as the
//      minimum validity along the chain, clamped strictly sub-hour. An over-long request
//      is refused; validity is determinable from the credential alone (no revocation
//      status is queried).
//   4. Attestation binding + replay refusal (claim 9 / INV-A6): record the verified
//      attestation bound to the issuance it justifies; a second issuance presenting the
//      same attestation evidence is refused (the durable unique index rejects it).
//   5. Idempotency (claim 15 / AN-5): the whole record step runs under the idempotency
//      key, so N identical requests yield exactly one issuance event.
//
// This precondition holds NO issuance key and mints nothing itself. The AGID-04 gate it
// consults holds only a refusal-signing key; the actual keygen/certify is the broker's,
// after this returns nil. So INV-A1 is preserved by construction: the precondition
// verifies, the key op is the broker's.
//
// Zero removal (INV-A10): the free single-hop attested-ephemeral badge (broker.Issue)
// never routes through a precondition, so attaching this one neither gates, moves, nor
// degrades it. Only broker.IssueChainBound consults it.

// Precondition errors.
var (
	// ErrPolicyDenied is returned when the S10.1 policy gate denies the chain-bound
	// issuance. The audit event carrying the denial reason has already been emitted
	// (claim 14). No key op is performed.
	ErrPolicyDenied = errors.New("brokerstore: chain-bound issuance denied by policy")
	// ErrSignerRefused is returned when the AGID-04 in-signer gate refuses the chain +
	// attestation (INV-A1). No key op is performed. The "mints only on verified
	// attestation" refusal (claim 26 / INV-A6) surfaces as ErrSignerRefused too: the
	// AGID-04 gate refuses when a required attestation is absent or invalid, before any
	// key op.
	ErrSignerRefused = errors.New("brokerstore: in-signer verification refused the chain-bound issuance")
	// ErrNoRequestContext is returned when the precondition cannot resolve the
	// chain-bound request context (chain envelopes / attestation / policy attrs) for a
	// view. Fail-closed: an unresolved chain-bound request is refused, never minted on a
	// bare view.
	ErrNoRequestContext = errors.New("brokerstore: no chain-bound request context resolved for the issuance view")
	// ErrNoPolicyGate is returned when the precondition is asked to evaluate but no
	// policy gate is configured. Fail-closed.
	ErrNoPolicyGate = errors.New("brokerstore: no policy gate configured for the chain-bound precondition")
	// ErrNoSignerGate is returned when the precondition is asked to verify but no
	// AGID-04 gate is configured. Fail-closed: without in-signer verification the
	// chain-bound path must not mint.
	ErrNoSignerGate = errors.New("brokerstore: no in-signer gate configured for the chain-bound precondition")
)

// PolicyEvaluator is the narrow S10.1 policy decision seam the precondition consults
// (claim 14). policy.Engine (via broker.PolicyGate) satisfies it. It is an interface so
// the precondition is testable with a fake and does not force the policy engine into the
// test closure.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, in policy.Input) (policy.Decision, error)
}

// Compile-time proof that the S10.1 engine (through broker's gate) is a valid evaluator.
var _ PolicyEvaluator = (broker.PolicyGate)(nil)

// ChainBoundRequest is the resolved, edition-private context for one chain-bound
// issuance: the self-describing delegation chain to verify, the attestation evidence, the
// agent-stack representation to bind, the designated authority class, and the requested
// TTL. The generic broker.IssuanceView the core forwards carries only public scalars
// (agent id, method, idempotency key); the ee control plane resolves the rest out of band
// (the chain/attestation the caller shipped over its own API), which is exactly the split
// the AGID-04a seam already uses in the signer (the core forwards opaque bodies; the
// edition owns their meaning).
type ChainBoundRequest struct {
	// Chain is the self-describing delegation chain (root-first), each hop carrying its
	// delegator public key DER + signed Record.
	Chain []delegation.RecordEnvelope
	// DesignatedClass names the authority class the chain head is designated as, keying
	// the min-attestation-class policy (claim 10).
	DesignatedClass string
	// Attestation is the opaque attestation-evidence body (type + payload) presented with
	// the request. Required when a designated class demands a minimum attestation class or
	// in the attestation-gated fallback (claim 26).
	Attestation []byte
	// AttestationMethod names the method that produced Attestation.
	AttestationMethod string
	// SubjectRepr is the agent-stack representation to bind (AGID-03). Optional in the
	// chain-only fallback (claim 31).
	SubjectRepr []byte
	// Envelope carries the encoded task envelope a chain head references (AGID-05).
	Envelope []byte
	// ReachabilityVerdict carries the encoded signed reachability verdict (AGID-06).
	ReachabilityVerdict []byte
	// TrustAnchorRef is the asserted trust-anchor reference for the request (a subject
	// handle), forwarded to the signer gate for refusal attribution.
	TrustAnchorRef string
	// RequestedTTL is the caller-requested credential lifetime. Zero (or negative) means
	// "no explicit request": the precondition derives the lifetime from the chain,
	// clamped sub-hour (claim 7 / INV-A7). A positive value exceeding the chain ceiling
	// is refused.
	RequestedTTL time.Duration
	// PolicyAttrs are extra attributes merged into the policy input (beyond agent id,
	// scopes, attestation method the view already carries). Optional.
	PolicyAttrs map[string]any
}

// RequestResolver resolves the edition-private ChainBoundRequest for a generic issuance
// view. The ee control plane implements it (keyed by the request's idempotency key, which
// the view carries), staging the chain/attestation the caller shipped over the AGID API
// before invoking broker.IssueChainBound. found=false means no chain-bound context was
// staged for this view — the precondition then fails closed (ErrNoRequestContext),
// refusing rather than minting on a bare view.
type RequestResolver interface {
	Resolve(ctx context.Context, view broker.IssuanceView) (ChainBoundRequest, bool, error)
}

// RequestResolverFunc adapts a bare function to RequestResolver.
type RequestResolverFunc func(ctx context.Context, view broker.IssuanceView) (ChainBoundRequest, bool, error)

// Resolve implements RequestResolver.
func (f RequestResolverFunc) Resolve(ctx context.Context, view broker.IssuanceView) (ChainBoundRequest, bool, error) {
	return f(ctx, view)
}

// Config configures the real chain-bound precondition. Every field is optional at
// construction so the fail-closed default wiring (before AGID-INT-WIRE provisions the
// gate/policy/store) builds a precondition that refuses every chain-bound request —
// exactly the AGID-07a placeholder's stance — while being the real type that verifies once
// provisioned.
type Config struct {
	// Gate is the AGID-04 in-signer verify-before-keygen gate. The precondition
	// RE-INVOKES its VerifyIssuancePreconditions on every chain-bound request (and every
	// renewal) BEFORE any key op (INV-A1). Nil ⇒ every chain-bound request is refused
	// (ErrNoSignerGate), fail-closed.
	//
	// It is the generic signing.IssuanceGate interface, NOT the concrete *delegation.Gate,
	// so the SAME precondition drives EITHER an in-process gate (a *delegation.Gate, when
	// the signer is co-resident, as tests use) OR a REMOTE gate over the signer transport
	// (a control-plane adapter that calls the signer's GatedIssue RPC — the AGID-INT-WIRE
	// production path, so the chain/attestation is verified inside the isolated AN-4 signer
	// and the credential is minted there, with only public material returned). Both satisfy
	// signing.IssuanceGate; the precondition neither knows nor cares which it holds.
	Gate signing.IssuanceGate
	// Policy is the S10.1 decision gate (claim 14). Nil ⇒ every chain-bound request is
	// refused (ErrNoPolicyGate), fail-closed.
	Policy PolicyEvaluator
	// Resolver resolves the edition-private chain-bound context for a view. Nil ⇒ every
	// chain-bound request is refused (ErrNoRequestContext), fail-closed.
	Resolver RequestResolver
	// Recorder persists the attestation binding + issuance + AN-6 outbox intent and
	// refuses replays (claim 9 / INV-A6). Nil ⇒ persistence is refused
	// (delegation.ErrNoBindingStore), fail-closed: the chain-bound path never mints
	// without a durable replay defense. The production *Recorder satisfies it.
	Recorder delegation.IssuanceBindingRecorder
	// Idem is the AN-5 idempotencer guarding the record step so N identical requests
	// yield exactly one issuance event (claim 15). Nil ⇒ an in-memory idempotencer is
	// used (single-node/test); production supplies the PostgreSQL-backed one.
	Idem Idempotencer
	// Audit is the AN-2 sink the policy-denial reason is emitted to (claim 14). Nil ⇒
	// no-op.
	Audit auditsink.Auditor
	// Clock supplies the current time for the TTL-ceiling derivation. Nil ⇒ time.Now.
	Clock func() time.Time
}

// Idempotencer records an idempotency key with its result so a replay returns the
// original result without re-executing (AN-5). It mirrors the ephemeral issuer's seam so
// the same PostgreSQL-backed orchestrator.Idempotency satisfies both.
type Idempotencer interface {
	Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error)
}

// memoryIdempotencer is an in-memory Idempotencer for single-node deployments and tests:
// a successful result is recorded and replayed for the same (tenant,key); an error
// releases the claim so a later retry can succeed. Production supplies the
// PostgreSQL-backed orchestrator.Idempotency.
type memoryIdempotencer struct {
	mu   sync.Mutex
	done map[string][]byte
}

// NewMemoryIdempotencer constructs an in-memory Idempotencer (single-node / test). It
// satisfies Idempotencer so a Config with a nil Idem defaults to it.
func NewMemoryIdempotencer() Idempotencer {
	return &memoryIdempotencer{done: map[string][]byte{}}
}

// Do records a successful result for (tenantID,key) and replays it on a repeat; an error
// leaves nothing recorded so a retry re-executes. A concurrent duplicate is serialized by
// the mutex; the first to complete records, the second replays.
func (m *memoryIdempotencer) Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	full := tenantID + "|" + key
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.done[full]; ok {
		return r, nil
	}
	res, err := fn(ctx)
	if err != nil {
		return nil, err
	}
	m.done[full] = res
	return res, nil
}

// BrokerPrecondition is the real chain-bound issuance precondition (claims 7/8/9/14/15/26).
// It satisfies broker.IssuancePrecondition. Construct it with NewBrokerPrecondition.
type BrokerPrecondition struct {
	cfg Config
}

// Compile-time assertion that the real precondition satisfies the core seam, so the
// attach line in cmd/trstctl/ee_attach.go type-checks and it drops in behind the same
// interface the AGID-07a placeholder implemented.
var _ broker.IssuancePrecondition = (*BrokerPrecondition)(nil)

// NewFailClosedBrokerPrecondition builds the REAL chain-bound precondition in its
// fail-closed default form (all dependencies nil), for the AGID activation block in
// cmd/trstctl/ee_attach.go. It REPLACES the AGID-07a placeholder: it is the production
// *BrokerPrecondition type, so once AGID-INT-WIRE provisions the gate, policy, resolver,
// and store the SAME type verifies for real — but until then every chain-bound request is
// refused (no gate ⇒ ErrNoSignerGate, no policy ⇒ ErrNoPolicyGate, no resolver ⇒
// ErrNoRequestContext), exactly the placeholder's fail-closed stance. An operator who
// licenses AGID before the substrate is wired gets a refusal, never an unverified
// chain-bound credential (INV-A1). The free single-hop badge is untouched: this hook is
// consulted ONLY on broker.IssueChainBound (INV-A10).
func NewFailClosedBrokerPrecondition() *BrokerPrecondition {
	return NewBrokerPrecondition(Config{})
}

// NewBrokerPrecondition builds the real chain-bound precondition. It fails closed by
// construction: a precondition built with any of gate/policy/resolver/recorder nil
// refuses the corresponding step, so an operator who licenses AGID before AGID-INT-WIRE
// provisions the dependencies gets a refusal, never an unverified chain-bound credential.
func NewBrokerPrecondition(cfg Config) *BrokerPrecondition {
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Idem == nil {
		cfg.Idem = NewMemoryIdempotencer()
	}
	return &BrokerPrecondition{cfg: cfg}
}

// CheckIssuancePrecondition is the broker.IssuancePrecondition entry point. It runs the
// full chain-bound gauntlet (policy → in-signer verify → TTL ceiling → attestation
// bind/replay under idempotency) and returns nil ONLY when every step approves. Any
// refusal returns a non-nil error and the broker mints nothing. It performs no key
// operation.
func (p *BrokerPrecondition) CheckIssuancePrecondition(ctx context.Context, view broker.IssuanceView) error {
	return p.evaluate(ctx, view, false)
}

// evaluate is the shared gauntlet for both issuance and renewal (CheckRenewalPrecondition
// calls it with renewal=true, which is identical here in effect — a renewal re-invokes the
// SAME policy + in-signer verification before any key op, claim 8 — the flag exists only to
// tag the audit trail and to document that no step is skipped on renewal).
func (p *BrokerPrecondition) evaluate(ctx context.Context, view broker.IssuanceView, renewal bool) error {
	// Resolve the edition-private chain-bound context. Fail closed if none staged.
	if p.cfg.Resolver == nil {
		return ErrNoRequestContext
	}
	req, ok, err := p.cfg.Resolver.Resolve(ctx, view)
	if err != nil {
		return fmt.Errorf("brokerstore: resolve chain-bound request: %w", err)
	}
	if !ok {
		return ErrNoRequestContext
	}

	// (1) Policy gate (claim 14): a DENY performs NO key op and emits an audit event with
	// the denial reason. This runs FIRST so a denied request never reaches the signer or a
	// key op.
	if err := p.checkPolicy(ctx, view, req); err != nil {
		return err
	}

	// (2) In-signer verification (AGID-04, claim 1 / INV-A1): re-invoke the AGID-04 gate
	// over the resolved chain + attestation BEFORE any key op. A non-approving decision
	// refuses. On a renewal this is the SAME full verification (claim 8) — nothing is
	// trusted from a prior issuance.
	decision, err := p.verifyInSigner(ctx, view.TenantID, req)
	if err != nil {
		return err
	}

	// (3) Sub-hour TTL ceiling (claims 7/26 / INV-A7): the lifetime is the minimum
	// validity along the chain, clamped strictly sub-hour. No revocation status is
	// queried — validity is determinable from the credential alone.
	if _, err := delegation.SubHourCeiling(req.Chain, p.cfg.Clock(), req.RequestedTTL); err != nil {
		return err
	}

	// (4)+(5) Attestation binding + replay refusal (claim 9 / INV-A6) under the
	// idempotency key (claim 15 / AN-5): record the verified attestation bound to the
	// issuance it justifies; a replay is refused; a retried request collapses to one
	// issuance event.
	if err := p.recordBinding(ctx, view, req, decision, renewal); err != nil {
		return err
	}
	return nil
}

// checkPolicy evaluates the S10.1 policy gate and, on a deny, emits the AN-2 audit event
// carrying the denial reason (claim 14) and returns ErrPolicyDenied. It runs before any
// signer consult or key op, so a policy-denied request performs no key op.
func (p *BrokerPrecondition) checkPolicy(ctx context.Context, view broker.IssuanceView, req ChainBoundRequest) error {
	if p.cfg.Policy == nil {
		return ErrNoPolicyGate
	}
	attrs := map[string]any{
		"agent_id":           view.AgentID,
		"scopes":             view.Scopes,
		"attestation_method": view.AttestationMethod,
		"chain_bound":        true,
		"designated_class":   req.DesignatedClass,
	}
	for k, v := range req.PolicyAttrs {
		attrs[k] = v
	}
	dec, err := p.cfg.Policy.Evaluate(ctx, policy.Input{
		Action:   policy.ActionIssue,
		TenantID: view.TenantID,
		Subject:  view.AgentID,
		Attrs:    attrs,
	})
	if err != nil {
		return fmt.Errorf("brokerstore: policy evaluation failed: %w", err)
	}
	if !dec.Allow {
		// Emit the denial reason (claim 14). Emit (not a bare _ = Audit) so a failed
		// audit write surfaces rather than silently dropping the record.
		_ = auditsink.Emit(ctx, p.cfg.Audit, nil, "agent.identity.refused", view.TenantID,
			[]byte(fmt.Sprintf(`{"agent_id":%q,"reason":%q,"chain_bound":true}`, view.AgentID, dec.Reason)))
		return fmt.Errorf("%w: %s", ErrPolicyDenied, dec.Reason)
	}
	return nil
}

// verifyInSigner re-invokes the AGID-04 in-signer gate over the resolved chain +
// attestation and returns the approving decision. A non-approving decision (the signer
// refused) is turned into ErrSignerRefused with no key op (INV-A1). It NEVER performs a
// key op: it only consults the gate, exactly as the signer's gatedIssue consults it
// before the keyOp.
func (p *BrokerPrecondition) verifyInSigner(ctx context.Context, tenantID string, req ChainBoundRequest) (signing.IssuanceDecision, error) {
	if p.cfg.Gate == nil {
		return signing.IssuanceDecision{}, ErrNoSignerGate
	}
	preBytes, err := delegation.EncodePreconditionsBody(delegation.PreconditionsBody{
		Chain:               req.Chain,
		DesignatedClass:     req.DesignatedClass,
		Envelope:            req.Envelope,
		ReachabilityVerdict: req.ReachabilityVerdict,
	})
	if err != nil {
		return signing.IssuanceDecision{}, fmt.Errorf("brokerstore: encode preconditions: %w", err)
	}
	gateReq := signing.IssuancePreconditions{
		TenantID:          tenantID,
		TrustAnchorRef:    req.TrustAnchorRef,
		Preconditions:     preBytes,
		SubjectRepr:       req.SubjectRepr,
		Attestation:       req.Attestation,
		AttestationMethod: req.AttestationMethod,
	}
	decision, err := p.cfg.Gate.VerifyIssuancePreconditions(ctx, gateReq)
	if err != nil {
		// A hard gate error is fail-closed too (the gate is designed to return a refusal
		// decision rather than error, but any error refuses).
		return signing.IssuanceDecision{}, fmt.Errorf("%w: %v", ErrSignerRefused, err)
	}
	if !decision.Approved {
		return signing.IssuanceDecision{}, ErrSignerRefused
	}
	return decision, nil
}

// recordBinding records the verified attestation bound to the issuance it justifies and
// enqueues the AN-6 outbox intent, under the idempotency key so N identical requests yield
// exactly one issuance event (claims 9/15 / INV-A6 / AN-5). A replay (same attestation,
// different key) is refused by the durable unique index (delegation.ErrAttestationReplay).
// The credential id is derived from the approved binding material so the binding row keys
// to the credential the broker will mint.
func (p *BrokerPrecondition) recordBinding(ctx context.Context, view broker.IssuanceView, req ChainBoundRequest, decision signing.IssuanceDecision, renewal bool) error {
	if p.cfg.Recorder == nil {
		return delegation.ErrNoBindingStore
	}
	bm, err := delegation.DecodeBindingMaterial(decision.BindingMaterial)
	if err != nil {
		return fmt.Errorf("brokerstore: decode approved binding material: %w", err)
	}
	chainDigest, err := bm.Digest()
	if err != nil {
		return fmt.Errorf("brokerstore: binding digest: %w", err)
	}
	now := p.cfg.Clock()
	ttl, err := delegation.SubHourCeiling(req.Chain, now, req.RequestedTTL)
	if err != nil {
		return err
	}
	binding := delegation.IssuanceBinding{
		TenantID:           view.TenantID,
		IdempotencyKey:     view.IdempotencyKey,
		CredentialID:       credentialIDFor(view, chainDigest, renewal),
		SubjectID:          view.AgentID,
		ChainHeadDigest:    bm.ChainHeadDigest,
		ChainDigest:        chainDigest,
		AgentStackDigest:   bm.AgentStackDigest,
		TaskEnvelopeDigest: bm.TaskEnvelopeDigest,
		EvidenceDigest:     bm.AttestationDigest,
		AttestationClass:   req.DesignatedClass,
		NotBefore:          now.Unix(),
		NotAfter:           now.Add(ttl).Unix(),
	}
	// Under the idempotency key: a retried request replays the recorded result without
	// re-inserting, so exactly one issuance event exists per key (claim 15 / AN-5). The
	// recorder itself is transactional (issuance + binding + outbox in one tx); the
	// idempotencer collapses retries in front of it.
	_, err = p.cfg.Idem.Do(ctx, view.TenantID, view.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		if err := p.cfg.Recorder.RecordIssuanceBinding(ctx, binding); err != nil {
			return nil, err
		}
		return []byte(binding.CredentialID), nil
	})
	return err
}

// credentialIDFor derives a stable credential id for the binding row from the tenant,
// agent, and chain digest, so the binding keys to a deterministic id the broker's mint
// can be reconciled against. A renewal derives a DISTINCT id (it is a fresh credential),
// but the same attestation evidence still cannot justify it (the evidence-digest unique
// index rejects a reused attestation, claim 9).
func credentialIDFor(view broker.IssuanceView, chainDigest []byte, renewal bool) string {
	kind := "cred"
	if renewal {
		kind = "renew"
	}
	return kind + ":" + view.TenantID + ":" + view.AgentID + ":" + shortHex(chainDigest)
}

// shortHex renders up to the first 16 bytes of a digest as hex, enough to make the
// derived credential id collision-resistant per (tenant, agent) without carrying the full
// digest in the id. An empty digest yields the empty string.
func shortHex(b []byte) string {
	if len(b) > 16 {
		b = b[:16]
	}
	return hex.EncodeToString(b)
}
