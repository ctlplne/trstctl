// SPDX-License-Identifier: LicenseRef-trstctl-EE

package translog

import (
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

func newSigner(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return s
}

// validRecord mints a valid dual-signed succession record for identity at epoch,
// with distinct fresh keys (so two calls yield different commitments).
func validRecord(t *testing.T, identity string, epoch uint64, policyRef string) succession.SuccessionRecord {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	succ, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	f := succession.CommitmentFields{
		DeploymentScope: "spiffe://d", IdentityID: identity, TenantID: "t",
		PredecessorEpoch: epoch - 1, Epoch: epoch,
		PredecessorAlg: crypto.ECDSAP256, PredecessorPub: pred.Public().DER,
		SuccessorAlg: crypto.ECDSAP256, SuccessorPub: succ.Public().DER,
		PolicyRef: policyRef, HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 2,
	}
	c, err := succession.Commit(f)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := pred.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	ss, err := succ.Sign(c, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	return succession.SuccessionRecord{Fields: f, PredecessorAtt: ps, Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: ss}}
}

// TestSTH_CarriesLogTimestamp: Append returns a stable index and a signed tree
// head carrying a log timestamp (claim 18).
func TestSTH_CarriesLogTimestamp(t *testing.T) {
	signer := newSigner(t)
	log := New(signer)
	idx0, sth0, err := log.Append([]byte("rec-0"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if idx0 != 0 || sth0.TreeSize != 1 {
		t.Fatalf("idx=%d size=%d, want 0,1", idx0, sth0.TreeSize)
	}
	if sth0.Timestamp == 0 {
		t.Fatal("STH carries no log timestamp")
	}
	if err := VerifySTH(signer.Public().DER, sth0); err != nil {
		t.Fatalf("STH signature invalid: %v", err)
	}
	idx1, sth1, err := log.Append([]byte("rec-1"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if idx1 != 1 || sth1.TreeSize != 2 {
		t.Fatalf("idx=%d size=%d, want 1,2", idx1, sth1.TreeSize)
	}
	if sth1.Timestamp < sth0.Timestamp {
		t.Fatal("STH timestamp went backwards")
	}
}

// TestInclusionProof_Verifies: an inclusion proof verifies for appended records
// and fails for non-members (claim 4).
func TestInclusionProof_Verifies(t *testing.T) {
	log := New(newSigner(t))
	var entries [][]byte
	var head STH
	for i := 0; i < 7; i++ {
		e := []byte{byte('a' + i)}
		entries = append(entries, e)
		_, sth, err := log.Append(e)
		if err != nil {
			t.Fatal(err)
		}
		head = sth
	}
	for i, e := range entries {
		proof, size, err := log.InclusionProof(i)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyInclusion(e, i, size, proof, head.RootHash) {
			t.Fatalf("inclusion proof for index %d failed", i)
		}
		if VerifyInclusion([]byte("nonmember"), i, size, proof, head.RootHash) {
			t.Fatalf("non-member verified at index %d", i)
		}
	}
}

// TestConsistency_Verifies: a consistency proof between two tree heads verifies
// and detects a tampered head (criterion 3).
func TestConsistency_Verifies(t *testing.T) {
	log := New(newSigner(t))
	var oldRoot []byte
	for i := 0; i < 3; i++ {
		_, sth, _ := log.Append([]byte{byte(i)})
		oldRoot = sth.RootHash
	}
	var newRoot []byte
	for i := 3; i < 8; i++ {
		_, sth, _ := log.Append([]byte{byte(i)})
		newRoot = sth.RootHash
	}
	proof, size, err := log.ConsistencyProof(3)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyConsistency(3, size, proof, oldRoot, newRoot) {
		t.Fatal("consistency proof failed")
	}
	if VerifyConsistency(3, size, proof, oldRoot, append([]byte{0}, newRoot...)) {
		t.Fatal("consistency accepted a tampered new head")
	}
}

// TestDowngradeEvidence_EpochCollisionDetected: two valid records for one identity
// sharing an epoch are detected as a collision; distinct epochs are not.
func TestDowngradeEvidence_EpochCollisionDetected(t *testing.T) {
	a := validRecord(t, "spiffe://d/db", 1, "policy:a")
	b := validRecord(t, "spiffe://d/db", 1, "policy:b")
	if !EpochCollision(a, b) {
		t.Fatal("two distinct records at the same epoch not detected as a collision")
	}
	c := validRecord(t, "spiffe://d/db", 2, "policy:c")
	if EpochCollision(a, c) {
		t.Fatal("records at different epochs falsely flagged")
	}
	// Different identity, same epoch: not a collision.
	d := validRecord(t, "spiffe://d/other", 1, "policy:a")
	if EpochCollision(a, d) {
		t.Fatal("records for different identities falsely flagged")
	}
}

// TestMisissuanceProof_ArtifactGenerated: a self-contained misissuance proof is
// built and independently verified (claim 11); an invalid or non-colliding pair
// is refused.
func TestMisissuanceProof_ArtifactGenerated(t *testing.T) {
	a := validRecord(t, "spiffe://d/db", 1, "policy:a")
	b := validRecord(t, "spiffe://d/db", 1, "policy:b")

	proof, err := BuildMisissuanceProof(a, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := VerifyMisissuanceProof(proof); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A tampered record breaks the proof.
	bad := proof
	bad.RecordA.PredecessorAtt = append([]byte{0}, bad.RecordA.PredecessorAtt...)
	if err := VerifyMisissuanceProof(bad); err == nil {
		t.Fatal("misissuance proof verified with a tampered record")
	}

	// A non-colliding pair is refused.
	c := validRecord(t, "spiffe://d/db", 2, "policy:c")
	if _, err := BuildMisissuanceProof(a, c); err == nil {
		t.Fatal("misissuance proof built from non-colliding records")
	}
}

// FuzzVerifyInclusion asserts the verifier never panics on arbitrary input.
func FuzzVerifyInclusion(f *testing.F) {
	f.Add([]byte("leaf"), 0, 1, []byte("proof"), []byte("root"))
	f.Fuzz(func(t *testing.T, leaf []byte, m, n int, proofBlob, root []byte) {
		// Bound sizes so the recursion terminates on adversarial n.
		if n < 0 || n > 1<<12 || m < -1 || m > 1<<12 {
			return
		}
		proof := [][]byte{proofBlob}
		_ = VerifyInclusion(leaf, m, n, proof, root)
		_ = VerifySTH(root, STH{TreeSize: n, RootHash: root, Timestamp: int64(m), Signature: proofBlob})
	})
}
