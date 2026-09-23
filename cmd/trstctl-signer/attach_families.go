// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	agiddelegation "trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/agentid/reach"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	vdecsigner "trstctl.com/trstctl/internal/decommission/signerwiring"
	pqc "trstctl.com/trstctl/internal/pqc"
	pqccompatlab "trstctl.com/trstctl/internal/pqc/compatlab"
	xrecdigest "trstctl.com/trstctl/internal/reconcile/digest"
	xrecplan "trstctl.com/trstctl/internal/reconcile/plan"
	"trstctl.com/trstctl/internal/signing"
	pcasdelegation "trstctl.com/trstctl/internal/succession/delegation"
	"trstctl.com/trstctl/internal/succession/kemcustody"
	"trstctl.com/trstctl/internal/succession/signerwiring"
)

// attach_families.go is the signer half of the core attach seam: the in-signer
// mechanisms of the core families — the PQC key factory, the AGID delegation
// gate and issuance key op, the XREC artifact signer and plan gate, the VDEC
// gated-destruction runtime, the PQC readiness-report signer, and the PCAS
// succession minter with its KEM custody — attach in every build. Until
// 2026-09-20 the PCAS minter sat behind lic.Has(FeaturePCAS) in ee_attach.go.
//
// Attaching the minter is AN-4-safe (INT-02a): succession's crypto primitives
// depend on the NATS-free internal/eventspec, not internal/events, so the
// minter's transitive closure links no message bus and no SQL driver (enforced
// by TestSignerDependencyClosure / TestNoHTTPServerLinkedIntoSigner).
func appendFamilyOptions(opts []signing.ServerOption, floorDir string, wrapper seal.KeyWrapper) []signing.ServerOption {
	opts = append(opts, signing.WithKeyFactory(pqc.NewSignerKeyFactory()))
	var anchorSource agiddelegation.RootAnchorSource
	var reachabilityTrust reach.VerdictTrustLookup
	var attestor agiddelegation.AttestationVerifier
	if floorDir != "" {
		anchorSource = agiddelegation.NewDurableAnchorStore(floorDir)
		reachabilityTrust = agiddelegation.NewDurableReachabilityTrustStore(floorDir).TrustLookup
		attestor = agiddelegation.NewDurableAttestationTrustStore(floorDir)
	}
	// Issuance-precondition gate (AGID-04a seam; AGID-04b verifier). Attached in
	// every build: the free single-hop issuance path is never gated
	// -- the control plane enforces issuance policy; AGID needs no edition license --
	// and the AGID-04b verifier ENGAGES only when delegation preconditions, attestation,
	// or an agent-stack subject are present, verifying each hop's signature+validity, the
	// per-hop narrowing under the AGID-01 partial order, and the attestation (with the
	// min-class gate) BEFORE any key op, and failing closed with a signed refusal (INV-A1).
	// The refusal-signing key is generated inside the signer as locked material and never
	// leaves the boundary. Root anchors, the AGID-02 projection-backed revocation reader,
	// and the attestation verifier are provisioned by the deployment (AGID-INT-WIRE);
	// until then a delegated chain fails closed at the root-anchor check rather than being
	// approved unverified.
	gate, _, err := agiddelegation.NewSignerGate(agiddelegation.SignerConfig{
		SignerID:            "trstctl-signer",
		AnchorSource:        anchorSource,
		Attestor:            attestor,
		ReachabilityTrust:   reachabilityTrust,
		RequireReachability: reachabilityTrust != nil,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: build AGID issuance gate: %v\n", err)
		os.Exit(1)
	}
	opts = append(opts, signing.WithIssuanceGate(gate))

	xrecSigner, err := xrecdigest.NewArtifactSigner(xrecdigest.ArtifactSignerConfig{SignerID: "trstctl-signer"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: build XREC artifact signer: %v\n", err)
		os.Exit(1)
	}
	xrecPlanKeys, err := xrecplan.LoadTrustedPlanKeys(floorDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: load XREC plan trust: %v\n", err)
		os.Exit(1)
	}
	xrecPlanGate, err := xrecplan.NewOperationGate(xrecplan.GateConfig{
		TrustedPlanKeys: xrecPlanKeys,
		TrustedWitnessKeys: map[string]crypto.PublicKey{
			xrecSigner.WitnessKeyID(): xrecSigner.WitnessPublic(),
		},
		ArtifactSigner: xrecSigner,
		SignerID:       "trstctl-signer",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: build XREC operation gate: %v\n", err)
		os.Exit(1)
	}
	opts = append(opts, signing.WithOperationGate(xrecPlanGate))

	vdecRuntime, err := vdecsigner.NewRuntime(vdecsigner.Config{SignerID: "trstctl-signer", FloorDir: floorDir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: build VDEC signer runtime: %v\n", err)
		os.Exit(1)
	}
	opts = append(opts, signing.WithGatedDestruction(vdecRuntime))

	// M1: the PQC readiness-report signer. It refuses every kind but
	// pqc-readiness-report, so adding it to the chain grants no authority over
	// the XREC or VDEC artifacts — a readiness report is a signed
	// recommendation about an irreversible migration and gets its own key.
	compatlabSigner, err := pqccompatlab.NewArtifactSigner("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: build PQC readiness signer: %v\n", err)
		os.Exit(1)
	}
	opts = append(opts, signing.WithArtifactSigner(chainedArtifactSigners{xrecSigner, vdecRuntime, compatlabSigner}))

	// The after-approval issuance KEY OP (AGID-INT-WIRE): the second half of the gated
	// mint. On an APPROVED decision from the gate above, it generates the agent credential
	// key INSIDE the signer and certifies it under the signer-held issuing CA, returning
	// only public material (INV-A1: the gate approves; this key op is the signer's mint).
	// Attached in every build beside the gate: the free single-hop path is approved by the
	// gate with an empty binding and this key op mints it, while every gated
	// (delegated/attested) issuance is verified before this runs.
	opts = append(opts, signing.WithIssuanceKeyOp(agiddelegation.NewSignerIssuanceKeyOp(agiddelegation.SignerConfig{SignerID: "trstctl-signer"})))
	// floorDir (the signer keystore dir) gives a DURABLE, restart-surviving epoch
	// floor (INT-05); empty (in-memory signer) => interim floor, matching ephemeral
	// keys.
	if floorDir != "" {
		kems, err := kemcustody.NewStore(floorDir, wrapper)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: build PCAS KEM custody: %v\n", err)
			os.Exit(1)
		}
		opts = append(opts, signing.WithKEMCustody(kems))
	} else {
		kems, err := kemcustody.NewStore("", nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: build PCAS KEM custody: %v\n", err)
			os.Exit(1)
		}
		opts = append(opts, signing.WithKEMCustody(kems))
	}
	var delegationConstraint interface {
		CheckAndBind(scope string, targetEpoch uint64) (string, error)
	}
	if floorDir != "" {
		delegationConstraint = pcasdelegation.NewDurableScopeStore(floorDir)
	}
	// Break-glass authority (claim 17): operator-provisioned PUBLIC key
	// inside the signer custody dir, never a control-plane input. Absent
	// leaves class downgrades refused unconditionally; present-but-invalid
	// fails startup rather than silently behaving as unconfigured.
	breakGlassPub, err := signerwiring.LoadBreakGlassAuthority(floorDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: %v\n", err)
		os.Exit(1)
	}
	m, err := signerwiring.NewProductionMinter(signerwiring.Config{
		SignerID: "trstctl-signer", FloorDir: floorDir, Delegation: delegationConstraint,
		BreakGlassAuthorityPubDER: breakGlassPub,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: build PCAS minter: %v\n", err)
		os.Exit(1)
	}
	opts = append(opts, signing.WithSuccessionMinter(m))
	return opts
}

type chainedArtifactSigners []signing.ArtifactSigner

func (c chainedArtifactSigners) SignArtifact(ctx context.Context, req signing.ArtifactSignRequest) (signing.ArtifactSignature, error) {
	var errs []error
	for _, signer := range c {
		if signer == nil {
			continue
		}
		sig, err := signer.SignArtifact(ctx, req)
		if err == nil {
			return sig, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return signing.ArtifactSignature{}, signing.ErrNoArtifactSigner
	}
	return signing.ArtifactSignature{}, errors.Join(errs...)
}

func (c chainedArtifactSigners) Destroy() {
	for _, signer := range c {
		if destroyer, ok := signer.(interface{ Destroy() }); ok {
			destroyer.Destroy()
		}
	}
}
