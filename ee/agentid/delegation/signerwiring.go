// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"trstctl.com/trstctl/ee/agentid/reach"
	"trstctl.com/trstctl/internal/crypto"
)

// signerwiring.go builds the production in-signer gate attached in
// cmd/trstctl-signer/ee_attach.go (the one allowlisted core edit replaces the 04a
// placeholder with NewSignerGate). It assembles the gate with production-safe,
// fail-closed defaults so the free single-hop issuance path stays free while every
// delegated / attested issuance is verified inside the AN-4 boundary before any key op.
//
// The refusal-signing key is generated INSIDE the signer as LOCKED, zeroizable material
// (AN-8) and never leaves the boundary; only its public form is exposed for verifying
// refusals. Root anchors and the projection-backed revocation reader are provisioned by
// the deployment (root-anchor provisioning + the AGID-02 projection adapter are the
// integration cards, AGID-INT-WIRE); until provisioned, the gate holds an empty trust
// store and a fail-closed revocation reader, so a delegated chain simply fails the
// root-anchor check with a signed refusal -- never an unverified approval. The
// min-attestation-class policy and the attestation verifier are likewise supplied by the
// deployment.

// SignerConfig configures the production gate at attach time. Every field is optional;
// the zero value yields a working, fail-closed gate that approves only the free
// single-hop path and refuses every delegated / attested request (no anchors, no
// attestor) with a signed refusal. Later integration wiring populates the fields.
type SignerConfig struct {
	// SignerID names this signer in signed refusals.
	SignerID string
	// Anchors are the root-anchor trust store entries, keyed by delegator key id. Empty
	// until root-anchor provisioning lands (AGID-INT-WIRE).
	Anchors map[string]RootAnchor
	// TenantAnchors are root anchors keyed by tenant id, then delegator key id.
	// This is the production-safe shape because two tenants may use the same key
	// id for different root principals.
	TenantAnchors map[string]map[string]RootAnchor
	// AnchorSource is an optional dynamic signer-local source, such as the durable
	// file-backed provisioning store. It is consulted after static tenant anchors
	// and before global single-tenant anchors.
	AnchorSource RootAnchorSource
	// Revocations is the AGID-02 projection-backed non-revocation reader. When nil, a
	// fail-closed reader is used that reports nothing revoked ONLY because there is no
	// chain to revoke on the free path; a real reader is required before delegated
	// issuance is enabled.
	Revocations RevocationReader
	// Attestor verifies attestation evidence read-only over internal/attest. When nil,
	// any request requiring attestation is refused.
	Attestor AttestationVerifier
	// MinClass is the min-attestation-class policy keyed by designated authority class.
	MinClass MinClassPolicy
	// Tools resolves tool aliases for the comparator.
	Tools *ToolRegistry
	// ReachabilityTrust resolves trusted control-plane reachability-verdict signer public
	// keys. Production supplies a signer-local durable source rooted at the signer
	// keystore directory so the signer verifies verdicts without SQL/NATS/HTTP.
	ReachabilityTrust reach.VerdictTrustLookup
	// ReachabilityWatermark bounds accepted graph watermarks. Nil accepts any non-empty
	// watermark; production may replace it with a stricter signer-held policy.
	ReachabilityWatermark reach.WatermarkPolicy
	// RequireReachability forces chain-bearing requests to carry a verdict.
	RequireReachability bool
	// RefusalAlgorithm is the algorithm for the in-signer refusal-signing key. Defaults
	// to ECDSA-P256.
	RefusalAlgorithm crypto.Algorithm
}

// NewSignerGate builds the production gate for attachment via signing.WithIssuanceGate.
// It generates the refusal-signing key inside the boundary (locked material) and
// assembles the fail-closed gate. It returns the gate and the refusal-signing public key
// (so operators/relying parties can verify refusals); the refusal private key stays in
// the signer.
func NewSignerGate(cfg SignerConfig) (*Gate, crypto.PublicKey, error) {
	alg := cfg.RefusalAlgorithm
	if alg == "" {
		alg = crypto.ECDSAP256
	}
	locked, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, crypto.PublicKey{}, err
	}
	refusalSigner := crypto.SignerFromDigestSigner(locked)

	revocations := cfg.Revocations
	if revocations == nil {
		// No projection adapter yet: a reader that reports nothing revoked. This is safe
		// ONLY because, absent root anchors, no delegated chain anchors -- every
		// multi-hop request is refused at the root-anchor check before revocation is
		// consulted. AGID-INT-WIRE replaces this with the real projection reader before
		// delegated issuance is enabled.
		revocations = NeverRevoked{}
	}

	roots := NewTrustStore(cfg.Anchors)
	if len(cfg.TenantAnchors) > 0 {
		roots = NewTenantTrustStore(cfg.TenantAnchors)
		if len(cfg.Anchors) > 0 {
			roots.anchors = NewTrustStore(cfg.Anchors).anchors
		}
	}
	if cfg.AnchorSource != nil {
		roots = roots.WithSource(cfg.AnchorSource)
	}

	gate, err := NewGate(Config{
		SignerID:              cfg.SignerID,
		Roots:                 roots,
		RefusalSigner:         refusalSigner,
		Revocations:           revocations,
		Attestor:              cfg.Attestor,
		MinClass:              cfg.MinClass,
		Tools:                 cfg.Tools,
		ReachabilityTrust:     cfg.ReachabilityTrust,
		ReachabilityWatermark: cfg.ReachabilityWatermark,
		RequireReachability:   cfg.RequireReachability,
	})
	if err != nil {
		locked.Destroy()
		return nil, crypto.PublicKey{}, err
	}
	return gate, refusalSigner.Public(), nil
}

// NewSignerIssuanceKeyOp builds the in-signer after-approval issuance KEY OP for
// attachment via signing.WithIssuanceKeyOp (AGID-INT-WIRE). It is the second half of the
// gated-issuance mint the signer drives over the transport: NewSignerGate verifies the
// chain/attestation BEFORE any key op, and THIS key op generates the agent credential key
// inside the signer's custody and certifies it under the signer-held issuing CA on an
// approved decision (INV-A1). It reuses the SignerConfig's SignerID (for the bootstrap
// issuing-CA common name); when the deployment provisions a durable issuing CA it is
// supplied here, otherwise the key op bootstraps a signer-internal CA inside the boundary.
// Attached beside NewSignerGate in cmd/trstctl-signer ee_attach so the gate and the key op
// are wired together.
func NewSignerIssuanceKeyOp(cfg SignerConfig) *IssuanceKeyOp {
	return NewIssuanceKeyOp(IssuanceKeyOpConfig{SignerID: cfg.SignerID})
}
