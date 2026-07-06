// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rpverify_test

import (
	"errors"
	"fmt"
	"testing"

	"trstctl.com/trstctl/ee/rpverify"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/recovery"
	"trstctl.com/trstctl/internal/crypto"
)

func recEcdsa(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// craftRecoveryRecord builds a recovery record directly (bypassing Mint) so a test
// can construct even an under-quorum record. threshold is the authorization
// threshold; numApprovals distinct rostered approvers sign.
func craftRecoveryRecord(t *testing.T, threshold, numApprovals int, withInclusion bool) (rec recovery.RecoveryRecord, trustRootPub, logPub []byte) {
	t.Helper()
	trustRoot := recEcdsa(t)
	succ := recEcdsa(t)

	roster := make([]recovery.Approver, 0, 3)
	signers := map[string]crypto.Signer{}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("a%d", i)
		s := recEcdsa(t)
		roster = append(roster, recovery.Approver{ID: id, PubDER: s.Public().DER})
		signers[id] = s
	}
	stmt := recovery.RecoveryStatement{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		Epoch: 2, SuccessorAlg: string(succ.Algorithm()), SuccessorPub: succ.Public().DER, Nonce: "n",
	}
	rosterSig, err := recovery.SignRoster(trustRoot, threshold, roster)
	if err != nil {
		t.Fatal(err)
	}
	var approvals []recovery.Approval
	for i := 0; i < numApprovals; i++ {
		id := fmt.Sprintf("a%d", i)
		sig, err := recovery.SignApproval(signers[id], stmt)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, recovery.Approval{ApproverID: id, Signature: sig})
	}
	fields := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		PredecessorEpoch: 1, Epoch: 2,
		PredecessorAlg: crypto.ECDSAP256, PredecessorPub: []byte{0x01},
		SuccessorAlg: succ.Algorithm(), SuccessorPub: succ.Public().DER,
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	commitment, err := succession.Commit(fields)
	if err != nil {
		t.Fatal(err)
	}
	possSig, err := succ.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	rec = recovery.RecoveryRecord{
		Fields:        fields,
		Possession:    succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: possSig},
		Authorization: recovery.RecoveryAuthorization{Statement: stmt, Threshold: threshold, Roster: roster, RosterSig: rosterSig, Approvals: approvals},
	}
	if withInclusion {
		leaf, err := succession.Commit(rec.Fields)
		if err != nil {
			t.Fatal(err)
		}
		rec.InclusionProof, logPub = realProofFor(t, leaf)
	}
	return rec, trustRoot.Public().DER, logPub
}

// TestRecovery_RequiresQuorumAndInclusion: the RP rejects a recovery record without
// the m-of-n authorization or without an inclusion proof, and accepts one with both
// (INV-12).
func TestRecovery_RequiresQuorumAndInclusion(t *testing.T) {
	// Under quorum (threshold 2, one approval) → rejected regardless of inclusion.
	under, root, logPub := craftRecoveryRecord(t, 2, 1, true)
	if err := rpverify.VerifyRecovery(under, rpverify.RecoveryOptions{TrustRootPubDER: root, MinThreshold: 2, STHVerifyKeyDER: logPub}); !errors.Is(err, recovery.ErrQuorumNotMet) {
		t.Fatalf("under-quorum recovery: got %v, want ErrQuorumNotMet", err)
	}

	// Quorum met but no inclusion proof → rejected.
	noIncl, root2, _ := craftRecoveryRecord(t, 2, 2, false)
	if err := rpverify.VerifyRecovery(noIncl, rpverify.RecoveryOptions{TrustRootPubDER: root2, MinThreshold: 2}); !errors.Is(err, rpverify.ErrRecoveryInclusionRequired) {
		t.Fatalf("recovery without inclusion: got %v, want ErrRecoveryInclusionRequired", err)
	}

	// Quorum + real inclusion proof under the log key → accepted.
	good, root3, logPub3 := craftRecoveryRecord(t, 2, 2, true)
	if err := rpverify.VerifyRecovery(good, rpverify.RecoveryOptions{TrustRootPubDER: root3, MinThreshold: 2, STHVerifyKeyDER: logPub3}); err != nil {
		t.Fatalf("valid recovery: %v", err)
	}

	// Quorum + a proof present but NO trusted log key → fails closed (no mock escape).
	if err := rpverify.VerifyRecovery(good, rpverify.RecoveryOptions{TrustRootPubDER: root3, MinThreshold: 2}); !errors.Is(err, rpverify.ErrRecoveryInclusionRequired) {
		t.Fatalf("recovery without a trusted log key: got %v, want ErrRecoveryInclusionRequired", err)
	}
}

// TestRPVerify_RecoveryStricterPolicy: the RP applies strictly stronger policy — an
// elevated approval threshold and a required out-of-band confirmation — beyond the
// record's own validity (INV-12 / INV-6).
func TestRPVerify_RecoveryStricterPolicy(t *testing.T) {
	rec, root, logPub := craftRecoveryRecord(t, 2, 2, true) // authorization threshold 2

	// RP demands threshold >= 3: rejected even though the record's own quorum is met.
	if err := rpverify.VerifyRecovery(rec, rpverify.RecoveryOptions{TrustRootPubDER: root, MinThreshold: 3, STHVerifyKeyDER: logPub}); !errors.Is(err, rpverify.ErrRecoveryThresholdTooLow) {
		t.Fatalf("elevated threshold: got %v, want ErrRecoveryThresholdTooLow", err)
	}

	// RP requires out-of-band confirmation, which is absent → rejected.
	if err := rpverify.VerifyRecovery(rec, rpverify.RecoveryOptions{
		TrustRootPubDER: root, MinThreshold: 2, STHVerifyKeyDER: logPub,
		ConfirmOutOfBand: func() error { return errors.New("no operator confirmation on file") },
	}); !errors.Is(err, rpverify.ErrRecoveryOutOfBand) {
		t.Fatalf("required OOB absent: got %v, want ErrRecoveryOutOfBand", err)
	}

	// All satisfied → accepted.
	if err := rpverify.VerifyRecovery(rec, rpverify.RecoveryOptions{
		TrustRootPubDER: root, MinThreshold: 2, STHVerifyKeyDER: logPub,
		ConfirmOutOfBand: func() error { return nil },
	}); err != nil {
		t.Fatalf("fully-satisfied recovery policy: %v", err)
	}
}
