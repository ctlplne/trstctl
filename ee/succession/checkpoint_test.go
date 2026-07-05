// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func checkpointSigner(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestCheckpoint_VerifyFromCheckpoint: a relying party verifies records from a
// signed epoch checkpoint instead of from genesis (claim 14).
func TestCheckpoint_VerifyFromCheckpoint(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	sc, err := BuildSampleChain(be, "spiffe://d", "spiffe://d/id", "t")
	if err != nil {
		t.Fatal(err)
	}
	signer := checkpointSigner(t)

	// Checkpoint at epoch 1 = record[0]'s successor key.
	cp := SignedEpochCheckpoint{
		DeploymentScope: sc.Genesis.DeploymentScope, IdentityID: sc.Genesis.IdentityID, TenantID: sc.Genesis.TenantID,
		Epoch: 1, Algorithm: sc.Records[0].Fields.SuccessorAlg, PublicKeyDER: sc.Records[0].Fields.SuccessorPub,
		LogTreeSize: 5, LogRootHash: []byte{1, 2, 3}, IssuedAt: 100,
	}
	cp, err = SignEpochCheckpoint(signer, cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEpochCheckpoint(signer.Public().DER, cp); err != nil {
		t.Fatalf("checkpoint signature: %v", err)
	}
	// Verify records after the checkpoint from the checkpoint anchor (no genesis).
	if err := VerifyChain(CheckpointAnchor(cp), sc.Records[1:], 0); err != nil {
		t.Fatalf("verify from checkpoint: %v", err)
	}
	other := checkpointSigner(t)
	if err := VerifyEpochCheckpoint(other.Public().DER, cp); err == nil {
		t.Fatal("checkpoint verified under the wrong key")
	}
}

// TestCheckpoint_CannotRegressLastAccepted: a chain not exceeding a checkpoint's
// epoch is rejected (the checkpoint epoch cannot be regressed) (claim 14).
func TestCheckpoint_CannotRegressLastAccepted(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	sc, err := BuildSampleChain(be, "spiffe://d", "spiffe://d/id", "t")
	if err != nil {
		t.Fatal(err)
	}
	cp := SignedEpochCheckpoint{Epoch: 2}
	if err := VerifyChain(sc.Genesis, sc.Records[:1], cp.Epoch); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("chain below checkpoint epoch: got %v, want ErrDowngrade", err)
	}
	if err := VerifyChain(sc.Genesis, sc.Records, cp.Epoch-1); err != nil {
		t.Fatalf("chain exceeding checkpoint epoch rejected: %v", err)
	}
}

// TestCheckpoint_BindsLogHead: the checkpoint binds the transparency-log head; a
// tampered head breaks the signature (claim 29).
func TestCheckpoint_BindsLogHead(t *testing.T) {
	signer := checkpointSigner(t)
	cp := SignedEpochCheckpoint{
		IdentityID: "id", TenantID: "t", Epoch: 2, Algorithm: crypto.ECDSAP256, PublicKeyDER: []byte{1},
		LogTreeSize: 7, LogRootHash: []byte{0xAA, 0xBB}, IssuedAt: 1,
	}
	cp, err := SignEpochCheckpoint(signer, cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEpochCheckpoint(signer.Public().DER, cp); err != nil {
		t.Fatal(err)
	}
	badRoot := cp
	badRoot.LogRootHash = append([]byte{0x00}, cp.LogRootHash...)
	if VerifyEpochCheckpoint(signer.Public().DER, badRoot) == nil {
		t.Fatal("tampered log root hash verified")
	}
	badSize := cp
	badSize.LogTreeSize++
	if VerifyEpochCheckpoint(signer.Public().DER, badSize) == nil {
		t.Fatal("tampered log tree size verified")
	}
}

// TestCheckpoint_DivergenceEvidencesEquivocation: two checkpoints at one epoch
// binding different log heads evidence equivocation (claim 29).
func TestCheckpoint_DivergenceEvidencesEquivocation(t *testing.T) {
	a := SignedEpochCheckpoint{IdentityID: "id", Epoch: 2, LogTreeSize: 7, LogRootHash: []byte{1}}
	b := SignedEpochCheckpoint{IdentityID: "id", Epoch: 2, LogTreeSize: 7, LogRootHash: []byte{2}}
	if !CheckpointsEquivocate(a, b) {
		t.Fatal("divergent log heads at the same epoch not flagged as equivocation")
	}
	if CheckpointsEquivocate(a, a) {
		t.Fatal("identical checkpoints flagged as equivocation")
	}
	diffEpoch := b
	diffEpoch.Epoch = 3
	if CheckpointsEquivocate(a, diffEpoch) {
		t.Fatal("different epochs flagged as equivocation")
	}
}
