// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package agent implements the workload-held-predecessor succession path (claim 19,
// FIG. 5): the predecessor private key is held by a workload agent, not the platform
// signer. The signer forms the commitment, the agent co-signs it as the predecessor,
// the signer verifies that first signature against the commitment IT supplied,
// generates the successor and contributes the successor signature, and assembles the
// record — so the first signature is obtained "under the control of" the signer
// (INV-1) without the platform ever holding the leaf key.
//
// The agent is a signing-oracle risk by construction, so it enforces the FIG. 5
// oracle-prevention rules: it never signs opaque bytes (it takes STRUCTURED
// commitment fields and reconstructs the domain-separated commitment itself), it
// signs only under a distinct key-usage Purpose, and it refuses any commitment whose
// identity / tenant / deployment scope or predecessor key is not its own. Epoch
// monotonicity is NOT the agent's job — it is enforced solely by the signer's floor
// (PCAS-05); an agent cannot advance or regress an epoch, because changing the epoch
// changes the commitment and the signer verifies the co-signature against its own.
//
// For workload-held-predecessor successions, transparency-log inclusion is MANDATORY
// on verification: it is what distinguishes the authentic, logged chain from a fork
// minted with an exfiltrated predecessor key. All crypto routes through the core
// AN-3 boundary.
package agent

import (
	"bytes"
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

// Purpose is the distinct key-usage purpose under which the workload agent will
// co-sign succession commitments — and only these. A request under any other
// purpose is refused, so the agent cannot be repurposed as a generic signing oracle
// (AN-4 key-usage separation).
const Purpose = "trstctl/pcas/workload-cosign/v1"

// Errors.
var (
	ErrForeignPurpose = errors.New("agent: refusing to co-sign outside the succession co-sign purpose")
	ErrForeignBinding = errors.New("agent: refusing a commitment whose identity/tenant/deployment is not this agent's")
	ErrNotPredecessor = errors.New("agent: refusing a commitment whose predecessor key is not this agent's")
	ErrMalformed      = errors.New("agent: refusing a malformed / non-domain-separated succession commitment")

	ErrCoSignInvalid     = errors.New("agent: predecessor co-signature does not verify against the supplied commitment")
	ErrInclusionRequired = errors.New("agent: workload-held-predecessor record requires a transparency-log inclusion proof")
)

// Config binds a workload agent to exactly one identity and holds its predecessor
// signing key (which never leaves the agent).
type Config struct {
	DeploymentScope string
	IdentityID      string
	TenantID        string
	Signer          crypto.Signer // the workload-held predecessor key
}

// Request is a structured co-sign request. It carries the STRUCTURED commitment
// fields — never opaque bytes — so the agent reconstructs and domain-separates the
// commitment itself and can never be coerced into signing an arbitrary value.
type Request struct {
	Purpose string
	Fields  succession.CommitmentFields
}

// Response carries the predecessor co-signature over the reconstructed commitment.
type Response struct {
	Signature []byte
}

// CoSigner is the workload agent's succession co-signer.
type CoSigner struct {
	cfg Config
}

// New validates cfg and returns a CoSigner.
func New(cfg Config) (*CoSigner, error) {
	if cfg.IdentityID == "" || cfg.TenantID == "" || cfg.DeploymentScope == "" {
		return nil, errors.New("agent: identity, tenant, and deployment scope are required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("agent: a predecessor signer is required")
	}
	return &CoSigner{cfg: cfg}, nil
}

// PublicDER returns the agent's predecessor public key (SubjectPublicKeyInfo DER).
func (a *CoSigner) PublicDER() []byte { return a.cfg.Signer.Public().DER }

// CoSign verifies the request against the agent's own configuration (FIG. 5
// oracle-prevention), reconstructs the domain-separated commitment from the
// structured fields, and returns the predecessor signature over it. It signs only
// under Purpose, only for its own identity/tenant/deployment, and only as its own
// predecessor key; a malformed or aliased request is refused.
func (a *CoSigner) CoSign(req Request) (Response, error) {
	if req.Purpose != Purpose {
		return Response{}, ErrForeignPurpose
	}
	f := req.Fields
	if f.IdentityID != a.cfg.IdentityID || f.TenantID != a.cfg.TenantID || f.DeploymentScope != a.cfg.DeploymentScope {
		return Response{}, ErrForeignBinding
	}
	if !bytes.Equal(f.PredecessorPub, a.cfg.Signer.Public().DER) {
		return Response{}, ErrNotPredecessor
	}
	// Reconstruct + domain-separate the commitment. A malformed/aliased request fails
	// here (INV-11), so the agent never produces a signature over non-succession bytes.
	commitment, err := succession.Commit(f)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	sig, err := a.cfg.Signer.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return Response{}, err
	}
	return Response{Signature: sig}, nil
}

// PredecessorCoSigner is the remote workload agent, from the signer's perspective.
type PredecessorCoSigner interface {
	CoSign(Request) (Response, error)
}

// MintWorkloadHeld runs the FIG. 5 commitment-transfer flow on the signer side. The
// signer supplies the predecessor-side fields and the successor it generated; this
// sets the successor into the commitment, requests the predecessor co-signature from
// the agent, verifies that first signature against the commitment IT supplied
// (INV-1: obtained under signer control), contributes the successor possession
// signature, and assembles the record. A co-signature over any other commitment
// (e.g. a substituted epoch) fails verification, so the agent cannot alter the
// succession.
func MintWorkloadHeld(fields succession.CommitmentFields, agent PredecessorCoSigner, successor crypto.Signer) (succession.SuccessionRecord, error) {
	fields.SuccessorAlg = successor.Algorithm()
	fields.SuccessorPub = successor.Public().DER

	commitment, err := succession.Commit(fields)
	if err != nil {
		return succession.SuccessionRecord{}, err
	}
	resp, err := agent.CoSign(Request{Purpose: Purpose, Fields: fields})
	if err != nil {
		return succession.SuccessionRecord{}, fmt.Errorf("agent co-sign: %w", err)
	}
	if err := crypto.VerifyMessage(fields.PredecessorPub, commitment, resp.Signature); err != nil {
		return succession.SuccessionRecord{}, fmt.Errorf("%w: %v", ErrCoSignInvalid, err)
	}
	succSig, err := successor.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return succession.SuccessionRecord{}, err
	}
	return succession.SuccessionRecord{
		Fields:         fields,
		PredecessorAtt: resp.Signature,
		Possession:     succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: succSig},
	}, nil
}

// VerifyWorkloadHeld is the relying-party verification for a workload-held-predecessor
// record. Beyond the base dual-attestation (VerifyRecord), a transparency-log
// inclusion proof is MANDATORY: it is what separates the authentic, logged chain from
// a fork minted with an exfiltrated predecessor key. A record with no inclusion proof,
// or one whose proof fails verifyInclusion, is rejected.
func VerifyWorkloadHeld(rec succession.SuccessionRecord, verifyInclusion func(proof []byte) error) error {
	if err := succession.VerifyRecord(rec); err != nil {
		return err
	}
	if len(rec.InclusionProof) == 0 || verifyInclusion == nil {
		return ErrInclusionRequired
	}
	if err := verifyInclusion(rec.InclusionProof); err != nil {
		return fmt.Errorf("agent: inclusion proof: %w", err)
	}
	return nil
}
