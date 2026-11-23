// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/agentid/reach"
	"trstctl.com/trstctl/internal/agentid/revoke"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/signing"
)

// signergate.go is the CONTROL-PLANE client adapter that turns the out-of-process signer
// into an AGID-04 in-signer gate the brokerstore chain-bound precondition consults
// (AGID-INT-WIRE). With this adapter attached, the precondition RE-INVOKES
// VerifyIssuancePreconditions over the resolved chain + attestation by calling the
// signer's GatedIssue RPC over the existing authenticated transport — so the chain,
// attestation, and reachability verdict are verified INSIDE the isolated AN-4 signer
// BEFORE any key op, and the credential is MINTED there, with only public material
// returned. The control plane requests but cannot forge: no private key crosses the
// boundary.
//
// It satisfies signing.IssuanceGate (the same interface the in-process *delegation.Gate
// satisfies), so the precondition neither knows nor cares whether the gate is co-resident
// (tests) or remote (production). The underlying transport is editionseam.IssuanceGate,
// satisfied by *signing.Client (the server wires it in via s.issuanceGate()).

// signerIssuanceGate adapts a remote signer transport (editionseam.IssuanceGate, i.e.
// *signing.Client) to the signing.IssuanceGate interface the brokerstore precondition holds.
// It carries the requested agent-key algorithm the signer generates inside the boundary on
// approval.
type signerIssuanceGate struct {
	transport    editionseam.IssuanceGate
	alg          crypto.Algorithm
	repo         *agidstore.Repo
	proofKey     reach.VerdictKeyRef
	signer       crypto.Signer
	requireProof bool
}

// NewSignerIssuanceGateWithRevocationProof is the production adapter. The
// control plane checks the current tenant projection immediately before signing
// a one-use authorization for the isolated signer.
func NewSignerIssuanceGateWithRevocationProof(transport editionseam.IssuanceGate, alg crypto.Algorithm, repo *agidstore.Repo, signer crypto.Signer, key reach.VerdictKeyRef) signing.IssuanceGate {
	if transport == nil {
		return nil
	}
	return &signerIssuanceGate{transport: transport, alg: alg, repo: repo, signer: signer, proofKey: key, requireProof: true}
}

// Compile-time proof the adapter is a valid in-signer gate for the precondition.
var _ signing.IssuanceGate = (*signerIssuanceGate)(nil)

// NewSignerIssuanceGate builds the control-plane adapter that drives a gated issuance over
// the signer transport. It returns a nil signing.IssuanceGate when transport is nil (no
// out-of-process signer configured), so the brokerstore precondition fails closed
// (ErrNoSignerGate) rather than minting an unverified chain-bound credential — the operator
// who licenses AGID before a signer is wired gets a refusal, never a forged credential
// (INV-A1). alg names the agent-credential key algorithm the signer generates inside the
// boundary on an approved issuance; the empty algorithm lets the signer's key op pick its
// default.
func NewSignerIssuanceGate(transport editionseam.IssuanceGate, alg crypto.Algorithm) signing.IssuanceGate {
	if transport == nil {
		return nil
	}
	return &signerIssuanceGate{transport: transport, alg: alg}
}

// VerifyIssuancePreconditions drives the gated issuance over the signer transport. It hands
// the opaque preconditions to the signer's GatedIssue RPC (which runs the attached AGID-04
// gate BEFORE any key op and mints inside the boundary on approval) and returns the decision
// the signer produced — Approved with the credential public material + binding on approval,
// or Approved:false with the signed refusal on a refusal. A transport error surfaces so the
// precondition fails closed (it never mints on an unreachable/erroring signer).
func (g *signerIssuanceGate) VerifyIssuancePreconditions(ctx context.Context, req signing.IssuancePreconditions) (signing.IssuanceDecision, error) {
	req.Algorithm = g.alg
	if g.requireProof {
		if g.repo == nil || g.signer == nil || g.proofKey.ID == "" {
			return signing.IssuanceDecision{}, fmt.Errorf("agentid signer gate: non-revocation signer is unavailable")
		}
		var body delegation.PreconditionsBody
		if len(req.Preconditions) > 0 {
			var err error
			body, err = delegation.DecodePreconditionsBody(req.Preconditions)
			if err != nil {
				return signing.IssuanceDecision{}, err
			}
		}
		checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		reader := revoke.NewDirectiveRevocationReader(g.repo, checkCtx)
		if err := checkRevocation(reader, req.TenantID, req.TrustAnchorRef, body); err != nil {
			return signing.IssuanceDecision{}, err
		}
		nonce, err := crypto.RandomBytes(32)
		if err != nil {
			return signing.IssuanceDecision{}, err
		}
		body.RevocationProof, err = delegation.SignRevocationProof(req, g.proofKey, g.signer, nonce, time.Now())
		if err != nil {
			return signing.IssuanceDecision{}, err
		}
		req.Preconditions, err = delegation.EncodePreconditionsBody(body)
		if err != nil {
			return signing.IssuanceDecision{}, err
		}
	}
	return g.transport.GatedIssue(ctx, req, g.alg)
}
