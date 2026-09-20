// SPDX-License-Identifier: BUSL-1.1

package succession_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
)

var signOpts = crypto.SignOptions{Hash: crypto.SHA256}

const (
	excDeployment = "spiffe://d"
	excIdentity   = "spiffe://d/id"
	excTenant     = "t"
)

// liveChain builds genesis → one succession record (G→K1 at epoch 1), returning the
// genesis, the chain, the live key K1, the signer-attestation key, and its roster.
func liveChain(t *testing.T) (succession.GenesisRecord, []succession.SuccessionRecord, crypto.Signer, crypto.Signer, map[string][]byte) {
	t.Helper()
	g, k1, attest := evSigner(t), evSigner(t), evSigner(t)
	genesis := succession.GenesisRecord{
		DeploymentScope: excDeployment, IdentityID: excIdentity, TenantID: excTenant,
		Algorithm: g.Algorithm(), PublicKey: g.Public().DER, Epoch: 0,
	}
	f := succession.CommitmentFields{
		DeploymentScope: excDeployment, IdentityID: excIdentity, TenantID: excTenant,
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: g.Algorithm(), PredecessorPub: g.Public().DER,
		SuccessorAlg: k1.Algorithm(), SuccessorPub: k1.Public().DER,
		HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	c, _ := succession.Commit(f)
	predAtt, _ := g.Sign(c, signOpts)
	poss, _ := k1.Sign(c, signOpts)
	rec := succession.SuccessionRecord{Fields: f, PredecessorAtt: predAtt, Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: poss}}
	return genesis, []succession.SuccessionRecord{rec}, k1, attest, map[string][]byte{"signer-1": attest.Public().DER}
}

// TestRevocation_AsChainedRecord: a revocation tombstone chains at the next epoch and
// a chain ending in it verifies as authentically revoked offline (PCAS-claim-36).
func TestRevocation_AsChainedRecord(t *testing.T) {
	genesis, chain, k1, attest, roster := liveChain(t)
	revoc, err := succession.BuildRevocation(k1, excDeployment, excIdentity, excTenant, 1, 1, 1000, attest, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	full := append(append([]succession.SuccessionRecord{}, chain...), revoc)

	if err := succession.VerifyChain(genesis, full, 0); err != nil {
		t.Fatalf("chain ending in a tombstone does not verify: %v", err)
	}
	if !succession.Revoked(full) {
		t.Fatal("chain ending in a tombstone is not reported revoked")
	}
	if succession.Revoked(chain) {
		t.Fatal("a live chain is reported revoked")
	}
	// The record type is signer-attested: altering it breaks the attestation.
	tampered := revoc
	tampered.RecordType = succession.RecOrdinary
	if _, err := succession.VerifyAttestation(roster, tampered); err == nil {
		t.Fatal("record type is not bound by the signer attestation (strippable)")
	}
}

// TestRevocation_MandatoryInclusion: a revocation record without an inclusion proof is
// refused at publish and rejected at verify; with one it is accepted (PCAS-claim-36).
func TestRevocation_MandatoryInclusion(t *testing.T) {
	_, _, k1, attest, roster := liveChain(t)
	revoc, err := succession.BuildRevocation(k1, excDeployment, excIdentity, excTenant, 1, 1, 1000, attest, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	okInclusion := func([]byte) error { return nil }

	if err := succession.RequireInclusionForExceptional(revoc); !errors.Is(err, succession.ErrExceptionalInclusion) {
		t.Fatalf("publish without inclusion: got %v, want ErrExceptionalInclusion", err)
	}
	if err := succession.VerifyExceptional(revoc, roster, okInclusion); !errors.Is(err, succession.ErrExceptionalInclusion) {
		t.Fatalf("verify without inclusion: got %v, want ErrExceptionalInclusion", err)
	}
	revoc.InclusionProof = []byte("inclusion-proof")
	if err := succession.RequireInclusionForExceptional(revoc); err != nil {
		t.Fatalf("publish with inclusion: %v", err)
	}
	if err := succession.VerifyExceptional(revoc, roster, okInclusion); err != nil {
		t.Fatalf("verify with inclusion: %v", err)
	}
}

// TestCeremony_ChainedRecord: break-glass ceremony and emergency issuances mint as
// distinct chained record types at the next epoch, each requiring inclusion (PCAS-claim-37).
func TestCeremony_ChainedRecord(t *testing.T) {
	genesis, chain, k1, attest, roster := liveChain(t)
	okInclusion := func([]byte) error { return nil }

	next := func(rt succession.RecordType) succession.SuccessionRecord {
		succ := evSigner(t)
		f := succession.CommitmentFields{
			DeploymentScope: excDeployment, IdentityID: excIdentity, TenantID: excTenant,
			PredecessorEpoch: 1, Epoch: 2,
			PredecessorAlg: k1.Algorithm(), PredecessorPub: k1.Public().DER,
			HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
		}
		rec, err := succession.BuildExceptional(f, k1, succ, rt, attest, "signer-1")
		if err != nil {
			t.Fatal(err)
		}
		rec.InclusionProof = []byte("inclusion-proof")
		return rec
	}

	for _, rt := range []succession.RecordType{succession.RecCeremony, succession.RecEmergency} {
		rec := next(rt)
		if rec.RecordType != rt || !succession.IsExceptional(rec) {
			t.Fatalf("record type = %q, want %q (exceptional)", rec.RecordType, rt)
		}
		if err := succession.VerifyChain(genesis, append(append([]succession.SuccessionRecord{}, chain...), rec), 0); err != nil {
			t.Fatalf("%s record does not chain at the next epoch: %v", rt, err)
		}
		if err := succession.VerifyExceptional(rec, roster, okInclusion); err != nil {
			t.Fatalf("%s record does not verify: %v", rt, err)
		}
		// Without inclusion it is refused (mandatory).
		noIncl := rec
		noIncl.InclusionProof = nil
		if err := succession.VerifyExceptional(noIncl, roster, okInclusion); !errors.Is(err, succession.ErrExceptionalInclusion) {
			t.Fatalf("%s without inclusion: got %v, want ErrExceptionalInclusion", rt, err)
		}
	}
}
