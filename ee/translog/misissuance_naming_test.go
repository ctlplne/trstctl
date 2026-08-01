// SPDX-License-Identifier: LicenseRef-trstctl-EE

package translog_test

import (
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/translog"
	"trstctl.com/trstctl/internal/crypto"
)

// attestedRecord builds a valid dual-signed record for identity at epoch, countersigned
// by the given attestation signer (naming signerID).
func attestedRecord(t *testing.T, identity string, epoch uint64, attest crypto.Signer, signerID string) succession.SuccessionRecord {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	succ, err := be.GenerateKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	fields := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: identity, TenantID: "t",
		PredecessorEpoch: epoch - 1, Epoch: epoch,
		PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		SuccessorAlg: succ.Algorithm(), SuccessorPub: succ.Public().DER,
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	commitment, err := succession.Commit(fields)
	if err != nil {
		t.Fatal(err)
	}
	predSig, _ := pred.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	succSig, _ := succ.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	rec := succession.SuccessionRecord{
		Fields: fields, PredecessorAtt: predSig,
		Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: succSig},
	}
	att, err := succession.Attest(attest, signerID, rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.SignerAttestation = att
	return rec
}

// TestMisissuanceProof_NamesMintingSigner: a misissuance proof over two equivocating
// records names the minting signer(s) from their attestations (PCAS-claim-28 / INV-13).
func TestMisissuanceProof_NamesMintingSigner(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	signerA, _ := be.GenerateKey(crypto.ECDSAP256)
	signerB, _ := be.GenerateKey(crypto.ECDSAP256)
	roster := map[string][]byte{"signer-A": signerA.Public().DER, "signer-B": signerB.Public().DER}

	// Two distinct records for one identity at the SAME epoch (an equivocation).
	a := attestedRecord(t, "spiffe://d/id", 1, signerA, "signer-A")
	b := attestedRecord(t, "spiffe://d/id", 1, signerB, "signer-B")

	proof, err := translog.BuildMisissuanceProof(a, b)
	if err != nil {
		t.Fatalf("build misissuance proof: %v", err)
	}
	nameA, nameB, err := proof.NamesMintingSigners(roster)
	if err != nil {
		t.Fatalf("name minting signers: %v", err)
	}
	if nameA != "signer-A" || nameB != "signer-B" {
		t.Fatalf("named signers = %q, %q; want signer-A, signer-B", nameA, nameB)
	}

	// A roster that does not include one of the signers cannot authenticate the naming.
	if _, _, err := proof.NamesMintingSigners(map[string][]byte{"signer-A": signerA.Public().DER}); err == nil {
		t.Fatal("naming succeeded against an incomplete roster")
	}
}
