// SPDX-License-Identifier: BUSL-1.1

package rpverify_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/rpverify"
	"trstctl.com/trstctl/internal/succession"
)

// exceptionalRecord builds an exceptional record. When withInclusion is set, it
// attaches a REAL transparency-log inclusion proof for the record's commitment and
// returns the log's public key (logPub) so the RP policy can verify it with the real
// Merkle verifier. When withInclusion is false, no proof is attached and logPub is nil.
func exceptionalRecord(t *testing.T, rt succession.RecordType, withInclusion bool) (rec succession.SuccessionRecord, roster map[string][]byte, logPub []byte) {
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
		leaf, err := succession.Commit(rec.Fields)
		if err != nil {
			t.Fatal(err)
		}
		rec.InclusionProof, logPub = realProofFor(t, leaf)
	}
	return rec, map[string][]byte{"signer-1": attest.Public().DER}, logPub
}

// TestCeremony_NoLedgerBypass: no exceptional path takes effect outside the ledger —
// a ceremony record without inclusion is refused; and the RP applies stricter policy
// (reject or elevate) to ceremony records while ordinary records are unaffected
// (PCAS-claim-37 / INV-15).
func TestCeremony_NoLedgerBypass(t *testing.T) {
	// Never logged (no inclusion proof) → refused: the ledger cannot be bypassed.
	unlogged, roster, _ := exceptionalRecord(t, succession.RecCeremony, false)
	if err := rpverify.VerifyExceptionalRecord(unlogged, rpverify.ExceptionalPolicy{SignerRoster: roster}); !errors.Is(err, succession.ErrExceptionalInclusion) {
		t.Fatalf("unlogged ceremony: got %v, want ErrExceptionalInclusion", err)
	}

	// Logged + default accept policy → accepted (real inclusion proof under the log key).
	rec, r2, logPub := exceptionalRecord(t, succession.RecCeremony, true)
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{SignerRoster: r2, STHVerifyKeyDER: logPub}); err != nil {
		t.Fatalf("logged ceremony under accept policy: %v", err)
	}
	// Stricter policy: reject ceremony outright.
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{SignerRoster: r2, STHVerifyKeyDER: logPub, RejectCeremony: true}); !errors.Is(err, rpverify.ErrCeremonyRejected) {
		t.Fatalf("reject-ceremony policy: got %v, want ErrCeremonyRejected", err)
	}
	// Accept-with-elevation: the elevated confirmation must succeed.
	if err := rpverify.VerifyExceptionalRecord(rec, rpverify.ExceptionalPolicy{
		SignerRoster: r2, STHVerifyKeyDER: logPub,
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
