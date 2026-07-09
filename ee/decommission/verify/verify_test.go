// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/ee/decommission/record"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

func TestVerify_OfflineFromRecordAndKeys(t *testing.T) {
	minter := newMinter(t)
	accounting := completionEvidence()
	rec := mintRecord(t, minter, 7, []record.SuccessorKey{successorKey(t, "succ-a", 8)}, accounting)
	head := headFor(t, rec)

	verdict, err := Verify(Request{
		Record:          rec,
		VerificationKey: minter.PublicKey(),
		LogHead:         head,
		Retained:        RetainedEpoch{StableKeyID: rec.Commitment.StableKeyID, Epoch: 7},
		Completion:      &accounting,
	})
	if err != nil {
		t.Fatalf("Verify offline: %v", err)
	}
	if verdict.Determination != DeterminationDestroyedAfterReprotection || verdict.StableKeyID != rec.Commitment.StableKeyID || verdict.FinalEpoch != 7 {
		t.Fatalf("verdict = %+v, want destroyed-after-reprotection for final epoch 7", verdict)
	}
}

func TestVerify_InclusionProofAgainstLogHead(t *testing.T) {
	minter := newMinter(t)
	accounting := completionEvidence()
	rec := mintRecord(t, minter, 7, nil, accounting)
	head := headFor(t, rec)

	if err := VerifyInclusionProof(rec, head); err != nil {
		t.Fatalf("VerifyInclusionProof: %v", err)
	}

	divergent := head
	divergent.RootDigest = crypto.SHA256Sum([]byte("different-held-head"))
	if err := VerifyInclusionProof(rec, divergent); !errors.Is(err, ErrInclusionProof) {
		t.Fatalf("divergent head error = %v, want ErrInclusionProof", err)
	}

	badProof := rec
	node, err := EncodeProofNode(ProofRight, crypto.SHA256Sum([]byte("different-proof-node")))
	if err != nil {
		t.Fatalf("EncodeProofNode: %v", err)
	}
	badProof.Commitment.Transparency.Proof = [][]byte{node}
	if err := VerifyInclusionProof(badProof, head); !errors.Is(err, ErrInclusionProof) {
		t.Fatalf("bad proof error = %v, want ErrInclusionProof", err)
	}
}

func TestVerify_FinalEpochNotBelowLastAccepted(t *testing.T) {
	minter := newMinter(t)
	accounting := completionEvidence()
	rec := mintRecord(t, minter, 7, nil, accounting)
	head := headFor(t, rec)

	_, err := Verify(Request{
		Record:          rec,
		VerificationKey: minter.PublicKey(),
		LogHead:         head,
		Retained:        RetainedEpoch{StableKeyID: rec.Commitment.StableKeyID, Epoch: 8},
	})
	if !errors.Is(err, ErrEpochFloor) {
		t.Fatalf("below retained epoch error = %v, want ErrEpochFloor", err)
	}

	_, err = Verify(Request{
		Record:          rec,
		VerificationKey: minter.PublicKey(),
		LogHead:         head,
		Retained:        RetainedEpoch{StableKeyID: "key://tenant-a/different", Epoch: 7},
	})
	if !errors.Is(err, ErrStableKeyMismatch) {
		t.Fatalf("stable key mismatch error = %v, want ErrStableKeyMismatch", err)
	}
}

func TestVerify_SuccessionChainCorrespondence(t *testing.T) {
	sc, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "scope-a", "key://tenant-a/root-ca", "tenant-a")
	if err != nil {
		t.Fatalf("BuildSampleChain: %v", err)
	}
	link := sc.Records[1]
	minter := newMinter(t)
	accounting := completionEvidence()
	rec := mintRecord(t, minter, link.Fields.PredecessorEpoch, []record.SuccessorKey{{
		ID:        "pcas-successor",
		Epoch:     link.Fields.Epoch,
		Algorithm: link.Fields.SuccessorAlg,
		PublicDER: link.Fields.SuccessorPub,
	}}, accounting)
	head := headFor(t, rec)
	ev := SuccessionEvidence{TrustRootPublicKeyDER: sc.TrustRootPubDER, Genesis: sc.Genesis, Chain: sc.Records}

	if _, err := Verify(Request{
		Record:          rec,
		VerificationKey: minter.PublicKey(),
		LogHead:         head,
		Retained:        RetainedEpoch{StableKeyID: rec.Commitment.StableKeyID, Epoch: link.Fields.PredecessorEpoch},
		Succession:      &ev,
	}); err != nil {
		t.Fatalf("Verify with furnished succession chain: %v", err)
	}

	bad := rec
	bad.Commitment.Successors[0].PublicDER = crypto.SHA256Sum([]byte("not-the-successor-public-key"))
	if err := VerifySuccessionCorrespondence(bad, ev); !errors.Is(err, ErrSuccessionChain) {
		t.Fatalf("bad successor correspondence error = %v, want ErrSuccessionChain", err)
	}
}

func TestVerify_RecomputeCompletionDigest(t *testing.T) {
	minter := newMinter(t)
	accounting := completionEvidence()
	rec := mintRecord(t, minter, 7, nil, accounting)

	if err := VerifyCompletionAccounting(rec, accounting); err != nil {
		t.Fatalf("VerifyCompletionAccounting: %v", err)
	}

	missing := accounting
	missing.Completed = nil
	if err := VerifyCompletionAccounting(rec, missing); !errors.Is(err, ErrUnaccountedDependent) {
		t.Fatalf("missing dependent accounting error = %v, want ErrUnaccountedDependent", err)
	}

	wrong := accounting
	wrong.Completed = append(wrong.Completed, depstate.Dependent{Class: depstate.DependentWrappedKey, ID: "wk-extra"})
	if err := VerifyCompletionAccounting(rec, wrong); !errors.Is(err, ErrCompletionDigest) {
		t.Fatalf("wrong completion digest error = %v, want ErrCompletionDigest", err)
	}
}

func newMinter(t *testing.T) *record.Minter {
	t.Helper()
	minter, err := record.NewMinter(record.Config{
		SignerID:  "test-vdec-verify-signer",
		Algorithm: crypto.ECDSAP256,
		Now:       func() time.Time { return time.Unix(1800000800, 0) },
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	t.Cleanup(minter.Destroy)
	return minter
}

func mintRecord(t *testing.T, minter *record.Minter, finalEpoch uint64, successors []record.SuccessorKey, accounting CompletionEvidence) record.SignedRecord {
	t.Helper()
	digest, err := CompletionEventsDigest("tenant-a", "key://tenant-a/root-ca", finalEpoch, accounting)
	if err != nil {
		t.Fatalf("CompletionEventsDigest: %v", err)
	}
	proof, err := proofPath()
	if err != nil {
		t.Fatalf("proofPath: %v", err)
	}
	rec, err := minter.Mint(context.Background(), record.MintRequest{
		TenantID:               "tenant-a",
		StableKeyID:            "key://tenant-a/root-ca",
		FinalEpoch:             finalEpoch,
		CompletionEventsDigest: digest,
		RequiredSetDigest:      crypto.SHA256Sum([]byte("required-set")),
		DestructionEvidence: record.EvidenceFromDestruction(gate.DestructionEvidence{
			Kind:               gate.TypeCustodyHSMDestroyed,
			TenantID:           "tenant-a",
			StableKeyID:        "key://tenant-a/root-ca",
			FinalEpoch:         finalEpoch,
			AttestationClass:   gate.ClassCertifiedHardware,
			AttestationClassID: gate.ClassCertifiedHardware.ID(),
			Record:             []byte("hsm destroy attestation statement"),
			Digest:             crypto.SHA256Sum([]byte("destroy evidence")),
		}),
		AuditChainHead:              "audit-head-after-destruction",
		Successors:                  successors,
		PolicyRef:                   "policy://destruction/root-ca",
		PolicyDecisionDigest:        crypto.SHA256Sum([]byte("policy-decision")),
		RevocationCompletionDigest:  crypto.SHA256Sum([]byte("revocation-completion")),
		TransparencyLogID:           "vdec-transparency-log",
		TransparencyInclusionProof:  proof,
		TransparencyTreeSize:        3,
		TransparencyCheckpointEpoch: 11,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return rec
}

func proofPath() ([][]byte, error) {
	left, err := EncodeProofNode(ProofLeft, crypto.SHA256Sum([]byte("left-sibling")))
	if err != nil {
		return nil, err
	}
	right, err := EncodeProofNode(ProofRight, crypto.SHA256Sum([]byte("right-sibling")))
	if err != nil {
		return nil, err
	}
	return [][]byte{left, right}, nil
}

func headFor(t *testing.T, rec record.SignedRecord) LogHead {
	t.Helper()
	head, err := HeadForRecord(rec)
	if err != nil {
		t.Fatalf("HeadForRecord: %v", err)
	}
	return head
}

func completionEvidence() CompletionEvidence {
	return CompletionEvidence{
		Registered: []depstate.Dependent{
			{Class: depstate.DependentCiphertext, ID: "ct-1"},
			{Class: depstate.DependentCredential, ID: "cred-1"},
			{Class: depstate.DependentDataSet, ID: "dataset-1"},
		},
		Completed: []depstate.Dependent{{Class: depstate.DependentCiphertext, ID: "ct-1"}},
		Released:  []depstate.Dependent{{Class: depstate.DependentCredential, ID: "cred-1"}},
		Erased:    []depstate.Dependent{{Class: depstate.DependentDataSet, ID: "dataset-1"}},
	}
}

func successorKey(t *testing.T, id string, epoch uint64) record.SuccessorKey {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	defer k.Destroy()
	pub := k.Public()
	return record.SuccessorKey{ID: id, Epoch: epoch, Algorithm: pub.Algorithm, PublicDER: pub.DER}
}
