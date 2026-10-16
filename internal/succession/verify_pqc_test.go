// SPDX-License-Identifier: BUSL-1.1

package succession_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/succession"
)

func TestVerifyRecordPurePQCSuccessorAndPredecessor(t *testing.T) {
	classical, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := pqc.GenerateKey(pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer pq.Destroy()
	pqMessageSigner := crypto.SignerFromDigestSigner(pq)
	verify := func(epoch uint64, predecessor, successor crypto.Signer) {
		t.Helper()
		fields := succession.CommitmentFields{
			DeploymentScope: "qa-pqc-cutover", IdentityID: "spiffe://qa.local/pqc",
			TenantID:         "11111111-1111-1111-1111-111111111111",
			PredecessorEpoch: epoch - 1, Epoch: epoch,
			PredecessorAlg: predecessor.Algorithm(), PredecessorPub: predecessor.Public().DER,
			SuccessorAlg: successor.Algorithm(), SuccessorPub: successor.Public().DER,
			HashAlg: succession.HashAlgSHA256,
		}
		commitment, err := succession.Commit(fields)
		if err != nil {
			t.Fatal(err)
		}
		predSig, err := predecessor.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
		if err != nil {
			t.Fatal(err)
		}
		succSig, err := successor.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
		if err != nil {
			t.Fatal(err)
		}
		record := succession.SuccessionRecord{
			Fields: fields, PredecessorAtt: predSig,
			Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: succSig},
		}
		if err := succession.VerifyRecord(record); err != nil {
			t.Fatalf("epoch %d: %v", epoch, err)
		}
		record.Possession.Signature[0] ^= 1
		if err := succession.VerifyRecord(record); err == nil {
			t.Fatalf("epoch %d: tampered PQC proof was accepted", epoch)
		}
	}
	verify(1, classical, pqMessageSigner)
	verify(2, pqMessageSigner, pqMessageSigner)
}

func TestVerifyRecordRejectsAlgorithmLabelThatDoesNotMatchClassicalKey(t *testing.T) {
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	fields := succession.CommitmentFields{
		DeploymentScope: "qa-pqc-cutover", IdentityID: "spiffe://qa.local/false-class",
		TenantID:         "11111111-1111-1111-1111-111111111111",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: crypto.ECDSAP384, PredecessorPub: key.Public().DER,
		SuccessorAlg: crypto.ECDSAP256, SuccessorPub: key.Public().DER,
		HashAlg: succession.HashAlgSHA256,
	}
	commitment, err := succession.Commit(fields)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	record := succession.SuccessionRecord{
		Fields: fields, PredecessorAtt: sig,
		Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: sig},
	}
	if err := succession.VerifyRecord(record); err == nil {
		t.Fatal("valid signatures over a false predecessor algorithm label were accepted")
	}
}
