// SPDX-License-Identifier: MPL-2.0

//go:build !trstctl_core

package main

import (
	"fmt"
	"os"

	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/ee/agentid/reach"
	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/ee/succession/signerwiring"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/signing"
)

// appendEEOptions attaches the Enterprise signer options. The PCAS succession minter
// is attached iff the deployment is licensed for PCAS (INT-02/INT-02a). Fail-closed:
// no license, or a license without the PCAS feature, means no minter is attached and
// the signer's MintSuccessor RPC returns UNIMPLEMENTED.
//
// Attaching the minter is AN-4-safe as of INT-02a: ee/succession's crypto primitives
// depend on the NATS-free internal/eventspec, not internal/events, so the minter's
// transitive closure links no message bus and no SQL driver (enforced by
// TestSignerDependencyClosure / TestNoHTTPServerLinkedIntoSigner).
func appendEEOptions(opts []signing.ServerOption, lic *license.Manager, floorDir string) []signing.ServerOption {
	opts = append(opts, signing.WithKeyFactory(eepqc.NewSignerKeyFactory()))
	var anchorSource delegation.RootAnchorSource
	var reachabilityTrust reach.VerdictTrustLookup
	var attestor delegation.AttestationVerifier
	if floorDir != "" {
		anchorSource = delegation.NewDurableAnchorStore(floorDir)
		reachabilityTrust = delegation.NewDurableReachabilityTrustStore(floorDir).TrustLookup
		attestor = delegation.NewDurableAttestationTrustStore(floorDir)
	}
	// Issuance-precondition gate (AGID-04a seam; AGID-04b verifier). Attached
	// UNCONDITIONALLY in the EE build: the free single-hop issuance path is never gated
	// -- license/policy gating is the control plane's job (AGID-07), not the signer's --
	// and the AGID-04b verifier ENGAGES only when delegation preconditions, attestation,
	// or an agent-stack subject are present, verifying each hop's signature+validity, the
	// per-hop narrowing under the AGID-01 partial order, and the attestation (with the
	// min-class gate) BEFORE any key op, and failing closed with a signed refusal (INV-A1).
	// The refusal-signing key is generated inside the signer as locked material and never
	// leaves the boundary. Root anchors, the AGID-02 projection-backed revocation reader,
	// and the attestation verifier are provisioned by the deployment (AGID-INT-WIRE);
	// until then a delegated chain fails closed at the root-anchor check rather than being
	// approved unverified. The core-only build attaches none, so the seam stays inert
	// there (INV-A10).
	gate, _, err := delegation.NewSignerGate(delegation.SignerConfig{
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

	// The after-approval issuance KEY OP (AGID-INT-WIRE): the second half of the gated
	// mint. On an APPROVED decision from the gate above, it generates the agent credential
	// key INSIDE the signer and certifies it under the signer-held issuing CA, returning
	// only public material (INV-A1: the gate approves; this key op is the signer's mint).
	// Attached UNCONDITIONALLY in the EE build beside the gate: the free single-hop path is
	// approved by the gate with an empty binding and this key op mints it, while every gated
	// (delegated/attested) issuance is verified before this runs. The core-only build
	// attaches none, so GatedIssue fails closed with UNIMPLEMENTED there (INV-A10).
	opts = append(opts, signing.WithIssuanceKeyOp(delegation.NewSignerIssuanceKeyOp(delegation.SignerConfig{SignerID: "trstctl-signer"})))
	if lic != nil && lic.Has(license.FeaturePCAS) {
		// floorDir (the signer keystore dir) gives a DURABLE, restart-surviving epoch
		// floor (INT-05); empty (in-memory signer) => interim floor, matching ephemeral
		// keys.
		m, err := signerwiring.NewProductionMinter(signerwiring.Config{SignerID: "trstctl-signer", FloorDir: floorDir})
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: build PCAS minter: %v\n", err)
			os.Exit(1)
		}
		opts = append(opts, signing.WithSuccessionMinter(m))
	}
	return opts
}
