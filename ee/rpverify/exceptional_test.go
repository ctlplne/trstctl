// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rpverify_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/rpverify"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

func exceptionalRecord(t *testing.T, rt succession.RecordType, withInclusion bool) (succession.SuccessionRecord, map[string][]byte) {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	pred, _ := be.GenerateKey(crypto.ECDSAP256)
	succ, _ := be.GenerateKey(crypto.ECDSAP384)
	attest, _ := be.GenerateKey(crypto.ECDSAP256)
	f := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	rec, err := succession.BuildExceptional(f, pred, succ, rt, attest, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	if withInclusion {
		rec.InclusionProof = []byte("inclusion-proof")
	}
	return rec, map[string][]byte{"signer-1": attest.Public().DER}
}

func okInclusion([]byte) error { return nil }

// TestCeremony_NoLedgerBypass: no exceptional path takes effect outside the ledger —
// a ceremony record without inclusion is refused; and the RP applies stricter policy
// (reject or elevate) to ceremony records while ordinary records are unaffected
// (claim 37 / INV-15).
func TestCeremony_NoLedgerBypass(t *testing.T) {
	// Never logged (no inclusion proof) → refused: the ledger cannot be bypassed.
	unlogged, roster := exceptionalRecord(t, succession.RecCeremony, false)
	if err := rpverify.VerifyExceptionalRecord(unlogged, rpverify.ExceptionalPolicy{SignerRoster: roster, VerifyInclusion: okInclusion}); !errors.Is(err, succession.ErrExceptionalInclusion) {
		t.Fatalf("unlogged ceremony: got %v, want ErrExceptionalInclusion", err)
	}

	// Logged + default accept policy → accepted.
	rec, r2 := exceptionalRecord(t, succession.RecCeremony, true)
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{SignerRoster: r2, VerifyInclusion: okInclusion}); err != nil {
		t.Fatalf("logged ceremony under accept policy: %v", err)
	}
	// Stricter policy: reject ceremony outright.
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{SignerRoster: r2, VerifyInclusion: okInclusion, RejectCeremony: true}); !errors.Is(err, rpverify.ErrCeremonyRejected) {
		t.Fatalf("reject-ceremony policy: got %v, want ErrCeremonyRejected", err)
	}
	// Accept-with-elevation: the elevated confirmation must succeed.
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{
		SignerRoster: r2, VerifyInclusion: okInclusion,
		ElevatedConfirm: func(succession.SuccessionRecord) error { return errors.New("no elevated approval on file") },
	}); !errors.Is(err, rpverify.ErrCeremonyRejected) {
		t.Fatalf("elevated-confirm failure: got %v, want ErrCeremonyRejected", err)
	}

	// Ordinary records are unaffected: no inclusion / attestation requirement.
	be := crypto.NewSoftwareBackend()
	pred, _ := be.GenerateKey(crypto.ECDSAP256)
	succ, _ := be.GenerateKey(crypto.ECDSAP384)
	f := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		SuccessorAlg: succ.Algorithm(), SuccessorPub: succ.Public().DER,
		HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	c, _ := succession.Commit(f)
	predAtt, _ := pred.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
	poss, _ := succ.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
	ordinary := succession.SuccessionRecord{Fields: f, PredecessorAtt: predAtt, Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: poss}}
	if err := rpverify.VerifyExceptionalRecord(ordinary, rpverify.ExceptionalPolicy{RejectCeremony: true}); err != nil {
		t.Fatalf("ordinary record affected by exceptional policy: %v", err)
	}
}
