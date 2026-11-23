// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"trstctl.com/trstctl/internal/agentid/reach"
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
// refusals. Root anchors and the public key for online non-revocation proofs are
// provisioned in the signer's local floor. The SQL-backed projection reader stays
// in the control plane (AN-4). Until the floors are provisioned, a delegated
// chain fails with a signed refusal. The
// min-attestation-class policy and the attestation verifier are likewise supplied by the
// deployment.
//
// SHIPPED-ARTIFACT / CRM SURFACE -- AGID-claim-30. Claim 30 is the non-transitory
// computer-readable-medium form of AGID-claim-1: a medium storing instructions that, when
// executed by one or more processors of a machine-credential control plane, cause it to
// perform that method. This file is the honest anchor for that form. It is the
// construction seam the SHIPPED trstctl-signer binary links: cmd/trstctl-signer/ee_attach.go
// calls NewSignerGate and NewSignerIssuanceKeyOp here, and the resulting program image --
// the release binary and the packages that carry it, produced from this source by the
// release pipeline -- is the medium whose stored instructions perform the method on
// execution. The end-to-end proof that the medium does so when executed is
// TestSignerBinaryAGIDRootAnchorsSurviveRestart in signer_subprocess_test.go, which builds
// the real binary, runs it as a separate process, and drives GatedIssue across the
// transport twice, including across a restart.

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
	// Revocations is an optional direct reader for controlled tests. Production
	// leaves it nil and requires a fresh signed proof for every gated issuance.
	Revocations RevocationReader
	// RevocationProofTrust and ProofConsumer are signer-local authorization
	// dependencies used when the SQL-backed reader cannot be linked into the
	// isolated process. A missing dependency refuses delegated issuance.
	RevocationProofTrust reach.VerdictTrustLookup
	ProofConsumer        ProofConsumer
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
	requireRevocationProof := revocations == nil && (cfg.AnchorSource != nil || len(cfg.Anchors) > 0 || len(cfg.TenantAnchors) > 0)
	if revocations == nil {
		// The signer has no SQL driver. A live root requires a signed online
		// authorization; NeverRevoked alone is never sufficient to approve.
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
		SignerID:               cfg.SignerID,
		Roots:                  roots,
		RefusalSigner:          refusalSigner,
		Revocations:            revocations,
		Attestor:               cfg.Attestor,
		MinClass:               cfg.MinClass,
		Tools:                  cfg.Tools,
		ReachabilityTrust:      cfg.ReachabilityTrust,
		ReachabilityWatermark:  cfg.ReachabilityWatermark,
		RequireReachability:    cfg.RequireReachability,
		RequireRevocationProof: requireRevocationProof,
		RevocationProofTrust:   cfg.RevocationProofTrust,
		ProofConsumer:          cfg.ProofConsumer,
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
