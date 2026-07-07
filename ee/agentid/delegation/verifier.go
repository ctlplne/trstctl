// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/ee/agentid/reach"
	"trstctl.com/trstctl/ee/agentid/taskenv"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// verifier.go is the custody-boundary heart of AGID (independent claim 1): the real
// signing.IssuanceGate that, BEFORE any private-key operation, verifies IN ORDER and
// FAILS CLOSED:
//
//  1. Each delegation record's signature + validity -- self-describing chain: each hop
//     carries its delegator public key DER; each hop's signature (via internal/crypto)
//     must chain to a ROOT ANCHOR held by the signer (the trust store the gate is
//     constructed with). Non-expiry, parent-hash linkage, depth accounting, and
//     non-revocation via the AGID-02 projection reader are all checked here.
//  2. Per-hop narrowing -- the AGID-01 comparator WithinParent proves each hop's
//     authority is no broader than its parent; ANY widening is refused.
//  3. Attestation evidence via internal/attest (read-only), including the
//     min-attestation-class gate: a designated authority class requires a minimum
//     attestation class; below-class evidence is refused NAMING the class not met
//     (claim 10).
//
// On ANY failure the gate returns IssuanceDecision{Approved:false, RefusalRecord:<signed
// refusal naming the failed hop+check>} with ZERO key ops; the caller appends an
// agent.refusal.recorded event. On success it returns Approved:true with BindingMaterial
// = the chain-head digest + agent-stack representation binding, and records the
// root-anchor phishing-resistant auth reference for the issuance event (claim 13). The
// real key op (agent keygen/certify) runs in the keyOp closure the signer supplies AFTER
// approval (see bind.go MintCredential); INV-A1 ordering is enforced by the core seam
// (issuancegate.go gatedIssue) which consults this gate BEFORE any key op.
//
// The gate holds NO issuance key: its only signing key is the refusal-signing
// crypto.Signer used to sign refusals. It performs the chain/attestation verification
// only; the after-approval keygen/certify is the signer's. This preserves INV-A1 by
// construction here (the gate approves; the key op is the signer's) and keeps the gate
// testable with software crypto + fakes.

// RootAnchor is one root anchor the signer holds in its trust store: the delegator
// public key DER that a valid chain's root hop must be signed by, plus a
// phishing-resistant auth reference recorded with the issuance event (claim 13). The
// AuthRef is an opaque handle to the phishing-resistant authenticator (a FIDO2/WebAuthn
// credential id, a hardware-token serial, ...) that bound the root principal; it is
// non-secret and recorded, never a password.
type RootAnchor struct {
	// PublicDER is the PKIX/DER SubjectPublicKeyInfo of the root delegator key. A
	// chain's root hop signature must verify against this key for the chain to anchor.
	PublicDER []byte
	// AuthRef is the phishing-resistant auth reference for the root principal, recorded
	// with the issuance event (claim 13). Non-secret.
	AuthRef string
}

// RootAnchorSource is an optional dynamic source for signer-held root anchors.
// The durable file store implements it so anchors registered by the control
// plane become visible to the next issuance without SQL/NATS in the signer.
type RootAnchorSource interface {
	Anchor(tenantID, keyID string) (RootAnchor, bool)
}

// TrustStore holds the signer's root anchors. Static global anchors are keyed by
// delegator key id for older tests and single-tenant fixtures. Tenant anchors are
// keyed by tenant id then key id. An optional dynamic source can resolve anchors
// from the signer's durable local provisioning directory. The gate is constructed
// with a TrustStore; a caller cannot inject its own anchor. A root hop whose key
// id is absent, or whose signature does not verify against the stored public key,
// is refused (the root-anchor check).
type TrustStore struct {
	anchors       map[string]RootAnchor
	tenantAnchors map[string]map[string]RootAnchor
	source        RootAnchorSource
}

// NewTrustStore builds a trust store from a map of delegator-key-id -> root anchor.
func NewTrustStore(anchors map[string]RootAnchor) *TrustStore {
	m := make(map[string]RootAnchor, len(anchors))
	for k, v := range anchors {
		m[k] = v
	}
	return &TrustStore{anchors: m}
}

// NewTenantTrustStore builds a trust store from tenant-scoped anchors. The input
// is copied so later caller mutation cannot alter signer trust.
func NewTenantTrustStore(anchors map[string]map[string]RootAnchor) *TrustStore {
	t := &TrustStore{tenantAnchors: map[string]map[string]RootAnchor{}}
	for tenantID, perTenant := range anchors {
		if perTenant == nil {
			continue
		}
		copied := make(map[string]RootAnchor, len(perTenant))
		for keyID, anchor := range perTenant {
			copied[keyID] = anchor
		}
		t.tenantAnchors[tenantID] = copied
	}
	return t
}

// WithSource returns a copy of the trust store that also consults source after
// static tenant/global anchors. Passing nil keeps the store unchanged.
func (t *TrustStore) WithSource(source RootAnchorSource) *TrustStore {
	if t == nil {
		return &TrustStore{source: source}
	}
	out := &TrustStore{
		anchors:       t.anchors,
		tenantAnchors: t.tenantAnchors,
		source:        source,
	}
	if source == nil {
		out.source = t.source
	}
	return out
}

// Anchor returns the root anchor for a delegator key id and whether it is trusted.
func (t *TrustStore) Anchor(keyID string) (RootAnchor, bool) {
	if t == nil {
		return RootAnchor{}, false
	}
	a, ok := t.anchors[keyID]
	return a, ok
}

// AnchorForTenant returns a tenant-scoped root anchor, falling back to global
// static anchors for existing single-tenant tests and fixtures.
func (t *TrustStore) AnchorForTenant(tenantID, keyID string) (RootAnchor, bool) {
	if t == nil {
		return RootAnchor{}, false
	}
	if perTenant := t.tenantAnchors[tenantID]; perTenant != nil {
		if a, ok := perTenant[keyID]; ok {
			return a, true
		}
	}
	if t.source != nil {
		if a, ok := t.source.Anchor(tenantID, keyID); ok {
			return a, true
		}
	}
	return t.Anchor(keyID)
}

// Config constructs the gate with its dependencies so it is testable with software
// crypto + fakes and wireable in cmd/trstctl-signer/ee_attach.go. Every dependency is
// an interface or a value the caller supplies; the gate reaches out to nothing global.
type Config struct {
	// SignerID names this signer in signed refusals (non-secret).
	SignerID string
	// Roots is the signer's root-anchor trust store. REQUIRED: a gate with no trust
	// store trusts no chain (every multi-hop chain would fail the root-anchor check),
	// so NewGate rejects a nil store fail-closed.
	Roots *TrustStore
	// RefusalSigner signs refusal artifacts inside the boundary (AN-3). REQUIRED: a
	// gate that cannot sign a refusal cannot satisfy the fail-closed spine, so NewGate
	// rejects a nil signer.
	RefusalSigner crypto.Signer
	// Revocations is the AGID-02 non-revocation reader consulted per hop. REQUIRED
	// (fail-closed by construction): production wiring supplies a projection-backed
	// reader; tests inject a fake (NeverRevoked / MapRevocationReader).
	Revocations RevocationReader
	// Attestor verifies attestation evidence over internal/attest (read-only).
	// Optional: when nil, a request that requires attestation (a designated class with
	// a positive min class, or an attestation-gated fallback) is refused, and a request
	// that requires none proceeds. Production supplies CoreAttestationVerifier.
	Attestor AttestationVerifier
	// MinClass maps a designated authority class to its minimum attestation class
	// (claim 10). Optional: an empty policy gates no class.
	MinClass MinClassPolicy
	// Tools resolves tool aliases for the comparator (AGID-01). Optional: a nil
	// registry resolves each tool to its normalized self.
	Tools *ToolRegistry
	// Clock supplies the current time for expiry checks. Optional: defaults to
	// time.Now. Injected in tests for determinism.
	Clock func() time.Time
	// IssuingCACertDER + IssuingCASigner are the signer-held issuing CA the keyOp
	// certifies agent credentials under. Optional on the gate itself (the gate does no
	// keygen); MintApproved uses them. When both are set, ApproveAndMint mints the
	// credential; otherwise the caller's own keyOp mints using bind.MintCredential.
	IssuingCACertDER []byte
	IssuingCASigner  crypto.DigestSigner
	// TaskEnvelopeTrust resolves a task-envelope requester key id to its public key DER
	// (AGID-05, claim 2). It is the signer-held registry of requester identities to
	// phishing-resistant keys the gate verifies a referenced task envelope's signature
	// against. Optional: a gate constructed WITHOUT it behaves exactly as AGID-04b for
	// envelope-free chains; but a chain whose head REFERENCES a task envelope is refused
	// fail-closed when this is nil (a referenced envelope must be verifiable). It is
	// never consulted unless a record references an envelope.
	TaskEnvelopeTrust taskenv.TrustLookup
	// ReachabilityTrust resolves a reachability-verdict signer key id to its public key
	// DER (AGID-06, claims 5/6). It is the signer-held registry of the reachability
	// engine's verdict-signing identities the gate verifies a presented reachability
	// verdict's signature against. Setting it (non-nil) ENABLES the reachability
	// precondition: a chain-bearing request must then carry a valid signed verdict for the
	// FINAL record's authority (an absent/unsigned/tampered/stale/Exceeded verdict is
	// refused fail-closed, no key op). A gate with this nil behaves exactly as AGID-05
	// (the reachability precondition is inert) UNLESS RequireReachability is set. It is the
	// out-of-signer verdict signer's public key, so graph computation stays OUT of the
	// signer (the signer trusts the signature, not a live graph).
	ReachabilityTrust reach.VerdictTrustLookup
	// ReachabilityWatermark is the signer's freshness policy for a reachability verdict's
	// graph watermark (AGID-06, claim 6). Optional: when nil, any non-empty watermark is
	// accepted (verification is still invariant to graph changes after the watermark,
	// because the signer trusts the signed digest). Production supplies a real staleness
	// policy (e.g. the verdict watermark must match/track the tenant's current graph
	// watermark). It is consulted only when a reachability verdict is verified.
	ReachabilityWatermark reach.WatermarkPolicy
	// RequireReachability forces the reachability precondition ON even when
	// ReachabilityTrust is nil: a chain-bearing request with reachability required but no
	// way to verify a verdict is refused fail-closed. It exists so an operator can assert
	// "no issuance without a reachability bound" independently of whether a trust lookup is
	// wired, closing an accidental-misconfiguration gap. Default false preserves AGID-05
	// behavior.
	RequireReachability bool
}

// Gate is the real in-signer verify-before-keygen issuance gate (claim 1). It
// implements signing.IssuanceGate. Construct it with NewGate.
type Gate struct {
	cfg Config
}

// Compile-time assertion that Gate satisfies the core seam interface, so the attach
// line in cmd/trstctl-signer/ee_attach.go type-checks.
var _ signing.IssuanceGate = (*Gate)(nil)

// Gate construction errors.
var (
	// ErrNoTrustStore is returned by NewGate when no root-anchor trust store is
	// supplied. Fail-closed: a gate that trusts no root must not be built silently.
	ErrNoTrustStore = fmt.Errorf("delegation: gate requires a root-anchor trust store")
	// ErrNoRefusalSigner is returned by NewGate when no refusal-signing key is
	// supplied. Fail-closed: the refusal spine (INV-A1) requires a signer.
	ErrNoRefusalSigner = fmt.Errorf("delegation: gate requires a refusal-signing key")
	// ErrNoRevocationReader is returned by NewGate when no revocation reader is
	// supplied. Fail-closed: the gate must be able to check non-revocation.
	ErrNoRevocationReader = fmt.Errorf("delegation: gate requires a revocation reader")
)

// NewGate constructs the gate, rejecting a configuration that cannot fail closed (no
// trust store, no refusal signer, no revocation reader). The returned gate is safe for
// concurrent use: it holds only read-only config and stateless signers.
func NewGate(cfg Config) (*Gate, error) {
	if cfg.Roots == nil {
		return nil, ErrNoTrustStore
	}
	if cfg.RefusalSigner == nil {
		return nil, ErrNoRefusalSigner
	}
	if cfg.Revocations == nil {
		return nil, ErrNoRevocationReader
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Gate{cfg: cfg}, nil
}

// verifyResult is the internal outcome of the in-order verification: either a refusal
// (named check + hop + detail) or an approval carrying the assembled binding material
// and the root-anchor auth reference to record (claim 13).
type verifyResult struct {
	refused  bool
	check    string
	hopIndex int
	detail   string

	binding   BindingMaterial
	authRef   string
	chainHead []byte
}

// VerifyIssuancePreconditions is the gate entry point (claim 1). It performs the full
// in-order verification and returns an IssuanceDecision. On refusal it signs a refusal
// artifact naming the failed hop+check and returns Approved:false with ZERO key ops. On
// approval it returns Approved:true with the binding material; the caller runs the key
// op (agent keygen/certify) AFTER approval. It NEVER performs a key op itself beyond
// signing the refusal.
func (g *Gate) VerifyIssuancePreconditions(_ context.Context, req signing.IssuancePreconditions) (signing.IssuanceDecision, error) {
	// Free single-hop path: a request that asserts NO delegation preconditions, NO
	// attestation, and NO agent-stack subject is the ungated single-hop issuance the
	// control plane owns (license/policy gating is AGID-07, not the signer's). It is
	// approved with an empty binding so the signer's own key-op path mints it, exactly
	// as the 04a placeholder did -- the 04b verifier ENGAGES only when delegation
	// preconditions, attestation, or an agent-stack subject are actually present. This
	// keeps the free path free while every gated path is verified fail-closed.
	if isUngatedSingleHop(req) {
		return signing.IssuanceDecision{Approved: true}, nil
	}
	res := g.verify(req)
	if res.refused {
		return g.refuse(req, res.check, res.hopIndex, res.detail)
	}
	// Approved: carry the binding material back for the signer's keyOp to certify. No
	// key op happens here.
	bmBytes, err := res.binding.Encode()
	if err != nil {
		// A binding we cannot encode is an internal failure: fail closed with a refusal
		// rather than approve an unbindable issuance.
		return g.refuse(req, CheckBindingTarget, -1, "binding encode failed")
	}
	return signing.IssuanceDecision{
		Approved:        true,
		BindingMaterial: bmBytes,
	}, nil
}

// verify runs the ordered checks (chain -> narrowing -> attestation -> binding) and
// returns a verifyResult. It performs NO key op and NO signing; the caller turns a
// refusal into a signed artifact. Ordering is load-bearing (INV-A1): every check that
// can refuse runs to completion before the binding is assembled, and the gate returns
// before the signer's keyOp is reached.
func (g *Gate) verify(req signing.IssuancePreconditions) verifyResult {
	body, err := decodePreconditions(req.Preconditions)
	if err != nil {
		return verifyResult{refused: true, check: CheckDecode, hopIndex: -1, detail: err.Error()}
	}

	now := g.cfg.Clock()

	// (1) Chain: signature + validity + linkage + depth + root-anchor + non-revocation.
	var chainHeadDigest []byte
	var rootAuthRef string
	if len(body.Chain) > 0 {
		cres := g.verifyChain(req.TenantID, body.Chain, now)
		if cres.refused {
			return cres
		}
		chainHeadDigest = cres.chainHead
		rootAuthRef = cres.authRef

		// (2) Per-hop narrowing (AGID-01 comparator monotonicity, re-checked here).
		if nres := g.verifyNarrowing(body.Chain); nres.refused {
			return nres
		}
	}

	// (3) Attestation + min-attestation-class gate (claim 10).
	ares := g.verifyAttestation(req, body)
	if ares.refused {
		return ares.verifyResult
	}
	attestationDigest := ares.detailBytes

	// Agent-stack representation (optional; required in the attestation-gated fallback,
	// absent in the chain-only fallback). The gate treats it as OPAQUE bytes and
	// structurally validates it fail-closed (no agentstack import inside the signer).
	var reprBytes []byte
	if len(req.SubjectRepr) > 0 {
		if err := validateReprBytes(req.SubjectRepr); err != nil {
			return refusal(CheckAgentStack, -1, err.Error())
		}
		reprBytes = req.SubjectRepr
	}

	// (4) Task envelope (AGID-05, claim 2 / INV-A4): when the chain HEAD references a
	// task envelope (its verified, signed TaskDigest is set), verify the referenced
	// envelope's SIGNATURE + EXPIRY here, as a PRECONDITION of the key op and BEFORE the
	// binding is assembled, and require its canonical digest to equal the head's
	// reference. On failure this refuses (CheckTaskEnvelope) with no key op. When no
	// record references an envelope, teres.chainHead is empty and nothing changes: the
	// AGID-04b behavior is exactly preserved (no regression). teres.chainHead here
	// carries the VERIFIED ENVELOPE DIGEST to bind (reusing the chainHead field as the
	// result's digest channel), not a chain digest.
	teres := g.verifyTaskEnvelope(headTaskDigest(body.Chain), body.Envelope, now)
	if teres.refused {
		return teres
	}
	taskEnvelopeDigest := teres.chainHead

	// (5) Reachability bound (AGID-06, claims 5/6 / INV-A5): when the reachability
	// precondition is engaged (a verdict is carried, or the gate REQUIRES reachability and
	// a chain is present), verify the SIGNED reachability verdict as a PRECONDITION of the
	// key op and BEFORE the binding is assembled. The verdict is bound to the FINAL
	// record's authority: the gate re-derives the head authority digest and requires the
	// verdict's SubjectDigest to equal it, checks the verdict signature + watermark, and
	// honors the ceiling determination. On failure this refuses (CheckReachability) with no
	// key op — an absent/unsigned/tampered/stale/Exceeded verdict is a ceiling violation.
	// The graph is an input to this REFUSAL GATE only: nothing is bound into the credential
	// from reachability (no regression to the binding; §6.3 — not a detection product).
	// When reachability is not engaged (no verdict and not required), this is inert and the
	// gate behaves exactly as AGID-05.
	if rres := g.verifyReachability(req.TenantID, body, now); rres.refused {
		return rres
	}

	// Binding target: at least one of a verified chain head or an agent-stack
	// representation must be present (claims 31/32 fallbacks each satisfy exactly one).
	if len(chainHeadDigest) == 0 && len(reprBytes) == 0 {
		return verifyResult{refused: true, check: CheckBindingTarget, hopIndex: -1, detail: "no chain and no agent-stack representation"}
	}

	bm, err := NewBindingMaterial(chainHeadDigest, reprBytes, body.DesignatedClass, attestationDigest, rootAuthRef, taskEnvelopeDigest)
	if err != nil {
		return verifyResult{refused: true, check: CheckBindingTarget, hopIndex: -1, detail: err.Error()}
	}

	return verifyResult{binding: bm, authRef: rootAuthRef, chainHead: chainHeadDigest}
}

// verifyChain verifies the self-describing chain hop-by-hop, root-first: linkage, each
// hop's signature against its CARRIED delegator key, non-expiry against now, depth
// accounting, and non-revocation via the reader; and that the ROOT hop's delegator key
// chains to a held root anchor (claim 1 chain limb + claim 13 root-anchor). It returns
// the chain-head digest and the root anchor's auth reference on success.
func (g *Gate) verifyChain(tenantID string, chain []RecordEnvelope, now time.Time) verifyResult {
	reg := g.cfg.Tools
	var parentDigest []byte
	var rootAuthRef string
	for i, env := range chain {
		rec := env.Record

		// Linkage: exactly one of root-anchor / parent-hash, and the parent-hash must
		// equal the previous hop's digest (spliced-chain and dangling-record defense).
		if err := rec.ValidateLinkage(); err != nil {
			return refusal(CheckChainLinkage, i, err.Error())
		}
		if i == 0 {
			if !rec.RootAnchor {
				return refusal(CheckChainLinkage, 0, "first hop is not root-anchored")
			}
		} else {
			if rec.RootAnchor {
				return refusal(CheckChainLinkage, i, "non-root hop is root-anchored")
			}
			if !bytesEqual(rec.ParentDigest, parentDigest) {
				return refusal(CheckChainLinkage, i, "parent digest does not match the previous hop")
			}
		}

		// Signature: verify this hop against its CARRIED delegator public key. A forged
		// or replayed record (any tampered signed field) fails here (record.go Verify).
		if len(env.DelegatorPublicDER) == 0 {
			return refusal(CheckHopSignature, i, "hop carries no delegator public key")
		}
		if err := rec.Verify(crypto.PublicKey{DER: env.DelegatorPublicDER}, reg); err != nil {
			return refusal(CheckHopSignature, i, "delegator signature invalid")
		}

		// Root-anchor: the ROOT hop's delegator key must be a held anchor whose stored
		// public key matches the carried key. This is what makes the carried keys
		// trustworthy -- an attacker who attaches their own key to a self-anchored
		// record still fails here because their key is not in the store.
		if i == 0 {
			anchor, ok := g.cfg.Roots.AnchorForTenant(tenantID, rec.DelegatorKey.ID)
			if !ok {
				return refusal(CheckRootAnchor, 0, "root delegator key id is not a held anchor")
			}
			if !bytesEqual(anchor.PublicDER, env.DelegatorPublicDER) {
				return refusal(CheckRootAnchor, 0, "root delegator key does not match the held anchor")
			}
			rootAuthRef = anchor.AuthRef
		}

		// Validity: this hop's validity window must contain now (non-expiry / not-yet).
		if !withinNow(rec.Validity, now) {
			return refusal(CheckExpiry, i, "hop validity window does not contain the issuance time")
		}

		// Depth accounting: a child must have strictly less remaining depth than its
		// parent, and no hop may claim more than its record's authority depth ceiling.
		if uint64(rec.DepthRemaining) > uint64(rec.Authority.Depth) {
			return refusal(CheckDepth, i, "hop depth-remaining exceeds its authority depth ceiling")
		}
		if i > 0 {
			prevRemaining := chain[i-1].Record.DepthRemaining
			if prevRemaining == 0 {
				return refusal(CheckDepth, i, "parent hop has no remaining delegation depth")
			}
			if rec.DepthRemaining >= prevRemaining {
				return refusal(CheckDepth, i, "hop did not decrement remaining delegation depth")
			}
		}

		// Digest of this hop (the parent linkage for the next hop, and -- for the last
		// hop -- the chain head that anchors the credential).
		d, err := rec.Digest(reg)
		if err != nil {
			return refusal(CheckChainLinkage, i, "hop digest computation failed")
		}

		// Non-revocation: this hop must not be revoked (ancestor revocation stops a
		// fresh descendant issuance). A reader error fails closed.
		revoked, err := g.cfg.Revocations.IsRevoked(tenantID, d)
		if err != nil {
			return refusal(CheckRevocation, i, "revocation reader error")
		}
		if revoked {
			return refusal(CheckRevocation, i, "hop is revoked")
		}

		parentDigest = d
	}
	return verifyResult{authRef: rootAuthRef, chainHead: parentDigest}
}

// verifyNarrowing re-checks the AGID-01 comparator monotonicity INSIDE the signer: each
// hop's authority must be no broader than its parent's (child ⊑ parent). ANY widening in
// ANY dimension is refused, naming the widening hop (INV-A2 enforcement half). This is
// the property the card requires re-checked in the signer, not merely trusted from the
// caller.
func (g *Gate) verifyNarrowing(chain []RecordEnvelope) verifyResult {
	reg := g.cfg.Tools
	for i := 1; i < len(chain); i++ {
		child := chain[i].Record.Authority
		parent := chain[i-1].Record.Authority
		if !WithinParent(child, parent, reg) {
			return refusal(CheckNarrowing, i, "hop widens authority beyond its parent")
		}
	}
	return verifyResult{}
}

// attResult carries the attestation-verify outcome plus the evidence digest to bind.
type attResult struct {
	verifyResult
	detailBytes []byte
}

// verifyAttestation verifies the attestation evidence (read-only over internal/attest)
// and enforces the min-attestation-class gate for the chain head's designated authority
// class (claim 10). Semantics:
//   - No designated class and no attestation body: nothing to verify; the evidence
//     digest is empty. (The chain-only fallback, claim 31.)
//   - A positive min class for the designated class, or a non-empty attestation body:
//     the evidence MUST verify and MUST meet the min class, else refuse -- and when it
//     is below class, NAME the class not met (claim 10). A verified attestation's
//     evidence digest is bound.
func (g *Gate) verifyAttestation(req signing.IssuancePreconditions, body PreconditionsBody) attResult {
	att, err := decodeAttestation(req.Attestation, req.AttestationMethod)
	if err != nil {
		return attResult{verifyResult: refusal(CheckAttestation, -1, err.Error())}
	}
	minClass := g.cfg.MinClass.Min(body.DesignatedClass)
	hasEvidence := len(att.Payload) > 0

	if minClass == ClassNone && !hasEvidence {
		// Nothing required and nothing supplied: no attestation binding.
		return attResult{}
	}
	if !hasEvidence {
		// A class is required but no evidence was supplied: refuse, naming the class.
		return attResult{verifyResult: refusal(CheckAttestation, -1, fmt.Sprintf("%v: required minimum class %s not met (no evidence)", ErrAttestationRequired, minClass))}
	}
	if g.cfg.Attestor == nil {
		// Evidence supplied but no verifier configured: fail closed (cannot verify).
		return attResult{verifyResult: refusal(CheckAttestation, -1, "no attestation verifier configured")}
	}
	verified, err := g.cfg.Attestor.VerifyEvidence(att.Method, att.Payload)
	if err != nil {
		return attResult{verifyResult: refusal(CheckAttestation, -1, "attestation evidence failed verification")}
	}
	if got := classOfAttestation(verified); got < minClass {
		// Below class: NAME the class not met (claim 10).
		return attResult{verifyResult: refusal(CheckAttestation, -1, fmt.Sprintf("%v: have %s, need %s", ErrBelowMinClass, got, minClass))}
	}
	return attResult{detailBytes: attestationEvidenceDigest(verified)}
}

// refuse signs a refusal artifact (naming the failed hop+check) with the gate's
// refusal-signing key and returns an un-approved decision carrying it. It performs NO
// key op beyond the refusal signature. A refusal that itself fails to sign still returns
// Approved:false (fail closed): the issuance is refused regardless.
func (g *Gate) refuse(req signing.IssuancePreconditions, check string, hopIndex int, detail string) (signing.IssuanceDecision, error) {
	art := RefusalArtifact{
		SignerID:      g.cfg.SignerID,
		TenantID:      req.TenantID,
		SubjectID:     subjectIDOf(req),
		FailedCheck:   check,
		HopIndex:      hopIndex,
		Detail:        detail,
		RequestDigest: requestDigest(req),
		IssuedAt:      g.cfg.Clock().Unix(),
	}
	signed, err := SignRefusal(g.cfg.RefusalSigner, art)
	if err != nil {
		// Could not sign: still refuse (no key op, no approval). Surface an unsigned
		// artifact so the caller records the refusal fact.
		enc, _ := EncodeRefusal(art)
		return signing.IssuanceDecision{Approved: false, RefusalRecord: enc}, nil
	}
	enc, err := EncodeRefusal(signed)
	if err != nil {
		return signing.IssuanceDecision{Approved: false}, nil
	}
	return signing.IssuanceDecision{Approved: false, RefusalRecord: enc}, nil
}

// refusal is a small constructor for a refused verifyResult.
func refusal(check string, hopIndex int, detail string) verifyResult {
	return verifyResult{refused: true, check: check, hopIndex: hopIndex, detail: detail}
}

// requestDigest is a domain-separated digest over the request's identifying,
// non-secret fields, bound into the refusal so it references the exact refused request
// without carrying evidence.
func requestDigest(req signing.IssuancePreconditions) []byte {
	var b []byte
	b = append(b, []byte("agid/agentid/request/v1")...)
	b = append(b, []byte(req.TenantID)...)
	b = append(b, []byte(req.TrustAnchorRef)...)
	b = append(b, []byte(req.AttestationMethod)...)
	b = append(b, req.Preconditions...)
	b = append(b, req.SubjectRepr...)
	b = append(b, req.Attestation...)
	return crypto.SHA256Sum(b)
}

// subjectIDOf derives a stable subject id for the refusal from the request's trust
// anchor reference (the caller-asserted subject handle). It is non-secret and used only
// for attribution.
func subjectIDOf(req signing.IssuancePreconditions) string { return req.TrustAnchorRef }

// isUngatedSingleHop reports whether a request asserts no gated preconditions at all:
// no delegation chain / designated class (empty or absent precondition body), no
// attestation evidence, and no agent-stack subject representation. Such a request is
// the free single-hop issuance path the control plane owns; the gate approves it with
// an empty binding rather than refusing (the 04b verifier engages only for delegated /
// attested / agent-stack issuance). It fails safe: any non-empty gated input flips this
// to false and routes through full verification.
func isUngatedSingleHop(req signing.IssuancePreconditions) bool {
	if len(req.SubjectRepr) > 0 || len(req.Attestation) > 0 {
		return false
	}
	body, err := decodePreconditions(req.Preconditions)
	if err != nil {
		// Undecodable preconditions are NOT the free path: route to verification, which
		// refuses fail-closed with a signed refusal.
		return false
	}
	return len(body.Chain) == 0 && body.DesignatedClass == ""
}

// withinNow reports whether now falls within the validity window (inclusive). A
// zero-valued window (NotBefore == 0 && NotAfter == 0) is treated as "no bound"
// (always valid) so a caller that omits validity is not force-expired; a set NotAfter is
// honored strictly.
func withinNow(w Window, now time.Time) bool {
	ts := now.Unix()
	if w.NotBefore == 0 && w.NotAfter == 0 {
		return true
	}
	if w.NotBefore != 0 && ts < w.NotBefore {
		return false
	}
	if w.NotAfter != 0 && ts > w.NotAfter {
		return false
	}
	return true
}

// bytesEqual is a length-then-content byte comparison (constant-time not required: these
// are public digests, not secrets).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// backgroundCtx returns a context for the read-only attestor call. The signer's
// attestors are local (push-based), so no caller deadline is threaded; a dedicated
// helper keeps context.Background out of the hot verify path's imports elsewhere.
func backgroundCtx() context.Context { return context.Background() }
