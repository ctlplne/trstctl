// SPDX-License-Identifier: LicenseRef-trstctl-EE

package recovery_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/recovery"
	"trstctl.com/trstctl/internal/crypto"
)

func ecdsa(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type approverKey struct {
	ap     recovery.Approver
	signer crypto.Signer
}

func mkApprover(t *testing.T, id string) approverKey {
	s := ecdsa(t)
	return approverKey{ap: recovery.Approver{ID: id, PubDER: s.Public().DER}, signer: s}
}

func statement(succ crypto.Signer, epoch uint64) recovery.RecoveryStatement {
	return recovery.RecoveryStatement{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		Epoch: epoch, SuccessorAlg: string(succ.Algorithm()), SuccessorPub: succ.Public().DER, Nonce: "n1",
	}
}

func buildAuth(t *testing.T, trustRoot crypto.Signer, stmt recovery.RecoveryStatement, threshold int, roster []approverKey, signers []approverKey) recovery.RecoveryAuthorization {
	t.Helper()
	rs := make([]recovery.Approver, len(roster))
	for i, a := range roster {
		rs[i] = a.ap
	}
	rosterSig, err := recovery.SignRoster(trustRoot, threshold, rs)
	if err != nil {
		t.Fatal(err)
	}
	var approvals []recovery.Approval
	for _, a := range signers {
		sig, err := recovery.SignApproval(a.signer, stmt)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, recovery.Approval{ApproverID: a.ap.ID, Signature: sig})
	}
	return recovery.RecoveryAuthorization{Statement: stmt, Threshold: threshold, Roster: rs, RosterSig: rosterSig, Approvals: approvals}
}

func recoveryFields() succession.CommitmentFields {
	return succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		PredecessorEpoch: 1, Epoch: 2, // lost predecessor at epoch 1; recover at 2
		PredecessorAlg: crypto.ECDSAP256, PredecessorPub: []byte{0x01, 0x02}, // the lost (unusable) key
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
}

// TestRecovery_QuorumRequired: a recovery mints only with the m-of-n tenant-root
// authorization; below threshold, a forged (non-rostered) approval, or a replayed
// approval do not reach quorum (INV-12).
func TestRecovery_QuorumRequired(t *testing.T) {
	trustRoot := ecdsa(t)
	succ := ecdsa(t)
	a1, a2, a3 := mkApprover(t, "a1"), mkApprover(t, "a2"), mkApprover(t, "a3")
	stmt := statement(succ, 2)

	// Valid 2-of-3.
	ok := buildAuth(t, trustRoot, stmt, 2, []approverKey{a1, a2, a3}, []approverKey{a1, a2})
	rec, err := recovery.Mint(recoveryFields(), ok, trustRoot.Public().DER, succ, 1)
	if err != nil {
		t.Fatalf("valid recovery mint: %v", err)
	}
	if err := recovery.VerifyRecord(rec, trustRoot.Public().DER); err != nil {
		t.Fatalf("valid recovery verify: %v", err)
	}

	// Below threshold (1 of 2 required).
	below := buildAuth(t, trustRoot, stmt, 2, []approverKey{a1, a2, a3}, []approverKey{a1})
	if _, err := recovery.Mint(recoveryFields(), below, trustRoot.Public().DER, succ, 1); !errors.Is(err, recovery.ErrQuorumNotMet) {
		t.Fatalf("below quorum: got %v, want ErrQuorumNotMet", err)
	}

	// Forged approval: a non-rostered impostor signs; it does not count.
	impostor := mkApprover(t, "a2") // claims id a2 but a different key
	forged := buildAuth(t, trustRoot, stmt, 2, []approverKey{a1, a2, a3}, []approverKey{a1})
	fsig, _ := recovery.SignApproval(impostor.signer, stmt)
	forged.Approvals = append(forged.Approvals, recovery.Approval{ApproverID: "a2", Signature: fsig})
	if _, err := recovery.Mint(recoveryFields(), forged, trustRoot.Public().DER, succ, 1); !errors.Is(err, recovery.ErrQuorumNotMet) {
		t.Fatalf("forged approval counted: got %v, want ErrQuorumNotMet", err)
	}

	// Replayed approval: the same approver twice counts once.
	replay := buildAuth(t, trustRoot, stmt, 2, []approverKey{a1, a2, a3}, []approverKey{a1})
	replay.Approvals = append(replay.Approvals, replay.Approvals[0]) // duplicate a1
	if _, err := recovery.Mint(recoveryFields(), replay, trustRoot.Public().DER, succ, 1); !errors.Is(err, recovery.ErrQuorumNotMet) {
		t.Fatalf("replayed approval inflated quorum: got %v, want ErrQuorumNotMet", err)
	}

	// A roster not rooted in the trust root is refused.
	unrooted := ok
	unrooted.RosterSig = append([]byte(nil), ok.RosterSig...)
	unrooted.RosterSig[0] ^= 0xFF
	if _, err := recovery.Mint(recoveryFields(), unrooted, trustRoot.Public().DER, succ, 1); !errors.Is(err, recovery.ErrRosterUnrooted) {
		t.Fatalf("unrooted roster: got %v, want ErrRosterUnrooted", err)
	}
}

// TestRecovery_StillEpochMonotonic: a recovery at or below the high-water is refused,
// exactly like an ordinary record (INV-12 / INV-3).
func TestRecovery_StillEpochMonotonic(t *testing.T) {
	trustRoot := ecdsa(t)
	succ := ecdsa(t)
	a1, a2 := mkApprover(t, "a1"), mkApprover(t, "a2")
	auth := buildAuth(t, trustRoot, statement(succ, 2), 2, []approverKey{a1, a2}, []approverKey{a1, a2})

	// high-water 2, recovery epoch 2 → refused (not strictly greater).
	if _, err := recovery.Mint(recoveryFields(), auth, trustRoot.Public().DER, succ, 2); !errors.Is(err, recovery.ErrEpochNotMonotonic) {
		t.Fatalf("recovery at high-water: got %v, want ErrEpochNotMonotonic", err)
	}
	// high-water 5, recovery epoch 2 → refused.
	if _, err := recovery.Mint(recoveryFields(), auth, trustRoot.Public().DER, succ, 5); !errors.Is(err, recovery.ErrEpochNotMonotonic) {
		t.Fatalf("recovery below high-water: got %v, want ErrEpochNotMonotonic", err)
	}
	// high-water 1, recovery epoch 2 → allowed.
	if _, err := recovery.Mint(recoveryFields(), auth, trustRoot.Public().DER, succ, 1); err != nil {
		t.Fatalf("recovery above high-water: %v", err)
	}
}

// TestRecovery_OrdinaryFlowCannotSkipPredecessorSig: the ordinary verify path
// requires a predecessor attestation, so no ordinary record can lack it — a
// predecessor-less record is only ever the distinct recovery type (INV-12).
func TestRecovery_OrdinaryFlowCannotSkipPredecessorSig(t *testing.T) {
	trustRoot := ecdsa(t)
	succ := ecdsa(t)
	a1, a2 := mkApprover(t, "a1"), mkApprover(t, "a2")
	auth := buildAuth(t, trustRoot, statement(succ, 2), 2, []approverKey{a1, a2}, []approverKey{a1, a2})
	rec, err := recovery.Mint(recoveryFields(), auth, trustRoot.Public().DER, succ, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Feeding the recovery record's fields + possession through the ORDINARY verifier
	// (which lacks any recovery-authorization awareness and has no PredecessorAtt) is
	// rejected — the ordinary path cannot accept a predecessor-less record.
	ordinaryView := succession.SuccessionRecord{Fields: rec.Fields, Possession: rec.Possession}
	if err := succession.VerifyRecord(ordinaryView); !errors.Is(err, succession.ErrPredecessorAttestation) {
		t.Fatalf("ordinary verify of a predecessor-less record: got %v, want ErrPredecessorAttestation", err)
	}
}

// TestRecovery_ChainContinues: after a recovery at epoch 2, an ordinary succession at
// epoch 3 chains from the recovery successor and verifies (chain-continuity).
func TestRecovery_ChainContinues(t *testing.T) {
	trustRoot := ecdsa(t)
	recSucc := ecdsa(t) // the recovery successor key (now the live key)
	a1, a2 := mkApprover(t, "a1"), mkApprover(t, "a2")
	auth := buildAuth(t, trustRoot, statement(recSucc, 2), 2, []approverKey{a1, a2}, []approverKey{a1, a2})
	rec, err := recovery.Mint(recoveryFields(), auth, trustRoot.Public().DER, recSucc, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Ordinary succession at epoch 3: predecessor = the recovery successor.
	next := ecdsa(t)
	f := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/id", TenantID: "t",
		PredecessorEpoch: rec.Fields.Epoch, Epoch: rec.Fields.Epoch + 1,
		PredecessorAlg: rec.Fields.SuccessorAlg, PredecessorPub: rec.Fields.SuccessorPub,
		SuccessorAlg: next.Algorithm(), SuccessorPub: next.Public().DER,
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 1000,
	}
	commitment, err := succession.Commit(f)
	if err != nil {
		t.Fatal(err)
	}
	predSig, _ := recSucc.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	succSig, _ := next.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	ordinary := succession.SuccessionRecord{
		Fields: f, PredecessorAtt: predSig,
		Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: succSig},
	}
	if err := succession.VerifyRecord(ordinary); err != nil {
		t.Fatalf("ordinary succession after recovery did not verify: %v", err)
	}
	if ordinary.Fields.PredecessorEpoch != rec.Fields.Epoch {
		t.Fatal("chain did not continue from the recovery epoch")
	}
}
