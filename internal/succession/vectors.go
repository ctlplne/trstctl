// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// SampleChain is a genesis record plus a verified succession chain, together with
// the trust-root public key needed to anchor it. It is the canonical conformance
// vector shared by the relying-party verifier (PCAS-07) and the release gate
// (PCAS-12), so those cards verify against the exact bytes this package mints.
type SampleChain struct {
	DeploymentScope string
	TrustRootPubDER []byte
	Genesis         GenesisRecord
	Records         []SuccessionRecord
}

// signCommitment signs a commitment (or genesis) digest through the core AN-3
// boundary. Ed25519 signs the message directly; ECDSA/RSA hash it per opts. The
// matching crypto.VerifyMessage recomputes consistently, so any registry
// algorithm round-trips.
func signCommitment(s crypto.Signer, digest []byte) ([]byte, error) {
	return s.Sign(digest, crypto.SignOptions{Hash: crypto.SHA256})
}

// BuildSampleChain mints a genesis + two-succession chain using the supplied key
// generator, signing each record's dual attestation over its commitment. The
// chain deliberately crosses algorithms (ECDSA-P256 -> ECDSA-P384 -> RSA-2048) so
// the vector exercises algorithm-agnostic verification through the core boundary.
// The returned chain verifies under VerifyGenesis + VerifyChain.
func BuildSampleChain(kg crypto.KeyGenerator, deploymentScope, identityID, tenantID string) (SampleChain, error) {
	trustRoot, err := kg.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		return SampleChain{}, fmt.Errorf("trust root: %w", err)
	}
	k0, err := kg.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		return SampleChain{}, fmt.Errorf("genesis key: %w", err)
	}
	k1, err := kg.GenerateKey(crypto.ECDSAP384)
	if err != nil {
		return SampleChain{}, fmt.Errorf("epoch-1 key: %w", err)
	}
	k2, err := kg.GenerateKey(crypto.RSA2048)
	if err != nil {
		return SampleChain{}, fmt.Errorf("epoch-2 key: %w", err)
	}

	genesis := GenesisRecord{
		DeploymentScope: deploymentScope,
		IdentityID:      identityID,
		TenantID:        tenantID,
		Algorithm:       crypto.ECDSAP256,
		PublicKey:       k0.Public().DER,
		Epoch:           0,
	}
	gd, err := GenesisDigest(genesis)
	if err != nil {
		return SampleChain{}, err
	}
	if genesis.TrustRootAtt, err = signCommitment(trustRoot, gd); err != nil {
		return SampleChain{}, fmt.Errorf("genesis attestation: %w", err)
	}

	rec1, err := mintRecord(deploymentScope, identityID, tenantID, 0,
		crypto.ECDSAP256, k0, crypto.ECDSAP384, k1, "policy:hybrid")
	if err != nil {
		return SampleChain{}, fmt.Errorf("record 1: %w", err)
	}
	rec2, err := mintRecord(deploymentScope, identityID, tenantID, 1,
		crypto.ECDSAP384, k1, crypto.RSA2048, k2, "policy:pure-pq")
	if err != nil {
		return SampleChain{}, fmt.Errorf("record 2: %w", err)
	}

	return SampleChain{
		DeploymentScope: deploymentScope,
		TrustRootPubDER: trustRoot.Public().DER,
		Genesis:         genesis,
		Records:         []SuccessionRecord{rec1, rec2},
	}, nil
}

// mintRecord forms the commitment for a succession from (predAlg, pred) to
// (succAlg, succ) at predecessorEpoch -> predecessorEpoch+1 and signs both limbs.
func mintRecord(deploymentScope, identityID, tenantID string, predecessorEpoch uint64,
	predAlg crypto.Algorithm, pred crypto.Signer,
	succAlg crypto.Algorithm, succ crypto.Signer, policyRef string) (SuccessionRecord, error) {

	f := CommitmentFields{
		DeploymentScope:  deploymentScope,
		IdentityID:       identityID,
		TenantID:         tenantID,
		PredecessorEpoch: predecessorEpoch,
		Epoch:            predecessorEpoch + 1,
		PredecessorAlg:   predAlg,
		PredecessorPub:   pred.Public().DER,
		SuccessorAlg:     succAlg,
		SuccessorPub:     succ.Public().DER,
		PolicyRef:        policyRef,
		HashAlg:          HashAlgSHA256,
		NotBefore:        1000,
		NotAfter:         1000000,
	}
	commitment, err := Commit(f)
	if err != nil {
		return SuccessionRecord{}, err
	}
	predSig, err := signCommitment(pred, commitment)
	if err != nil {
		return SuccessionRecord{}, fmt.Errorf("predecessor sign: %w", err)
	}
	succSig, err := signCommitment(succ, commitment)
	if err != nil {
		return SuccessionRecord{}, fmt.Errorf("successor sign: %w", err)
	}
	return SuccessionRecord{
		Fields:         f,
		PredecessorAtt: predSig,
		Possession:     PossessionProof{Kind: ProofSuccessorSignature, Signature: succSig},
	}, nil
}
