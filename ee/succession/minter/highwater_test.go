// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter_test

import (
	"errors"
	"sync"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
)

const hwID = "spiffe://d/id"

// fakeCounter is an in-process stand-in for a hardware monotonic counter: its value
// is external to the signer's sealed state and never lowers.
type fakeCounter struct {
	mu sync.Mutex
	v  map[string]uint64
}

func newFakeCounter() *fakeCounter { return &fakeCounter{v: map[string]uint64{}} }

func (c *fakeCounter) Value(slot string) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.v[slot], nil
}
func (c *fakeCounter) Bump(slot string, to uint64) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if to > c.v[slot] {
		c.v[slot] = to
	}
	return c.v[slot], nil
}

func hwSigner(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func hwCheckpoint(t *testing.T, signer crypto.Signer, epoch uint64, issuedAt int64) succession.SignedEpochCheckpoint {
	t.Helper()
	cp, err := succession.SignEpochCheckpoint(signer, succession.SignedEpochCheckpoint{
		DeploymentScope: "spiffe://d", IdentityID: hwID, TenantID: "t",
		Epoch: epoch, Algorithm: crypto.ECDSAP256, PublicKeyDER: []byte{1}, IssuedAt: issuedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// TestHighWater_RestoreCannotRegress: after restoring an older sealed value, both the
// hardware counter and a presented checkpoint pin the floor to the newest epoch, and
// minting below it stays refused (PCAS-claim-21 / INV-3).
func TestHighWater_RestoreCannotRegress(t *testing.T) {
	// Hardware-counter backing: counter still reads 5 though sealed was restored to 2.
	ctr := newFakeCounter()
	_, _ = ctr.Bump(hwID, 5)
	hw := minter.NewHighWater(map[string]uint64{hwID: 2}, minter.WithMonotonicCounter(ctr))
	if f, _ := hw.Floor(hwID); f != 5 {
		t.Fatalf("counter-backed floor = %d, want 5 (restore cannot regress)", f)
	}
	if err := hw.SealAdvance(hwID, 4); !errors.Is(err, minter.ErrRegress) {
		t.Fatalf("advance below counter: got %v, want ErrRegress", err)
	}
	if err := hw.SealAdvance(hwID, 6); err != nil {
		t.Fatalf("advance above counter rejected: %v", err)
	}

	// Presentation backing: restore to 2, present a verified checkpoint at epoch 5.
	key := hwSigner(t)
	hw2 := minter.NewHighWater(map[string]uint64{hwID: 2}, minter.WithCheckpointKey(key.Public().DER))
	if err := hw2.AdoptPresented(hwCheckpoint(t, key, 5, 100)); err != nil {
		t.Fatalf("adopt presented: %v", err)
	}
	if f, _ := hw2.Floor(hwID); f != 5 {
		t.Fatalf("presentation-backed floor = %d, want 5", f)
	}
	if err := hw2.SealAdvance(hwID, 3); !errors.Is(err, minter.ErrRegress) {
		t.Fatalf("advance below presented: got %v, want ErrRegress", err)
	}
}

// TestHighWater_QuorumAdvance: an unacknowledged advance does not seal; after a quorum
// of distinct instances acks, the advance is durable and survives a single instance's
// loss (PCAS-claim-21).
func TestHighWater_QuorumAdvance(t *testing.T) {
	hw := minter.NewHighWater(nil, minter.WithQuorum(2))
	if durable, err := hw.ProposeAdvance(hwID, 1, "instance-a"); err != nil || durable {
		t.Fatalf("first ack: durable=%v err=%v, want not-durable", durable, err)
	}
	if f, _ := hw.Floor(hwID); f != 0 {
		t.Fatalf("floor advanced on a single ack: %d", f)
	}
	if durable, err := hw.ProposeAdvance(hwID, 1, "instance-b"); err != nil || !durable {
		t.Fatalf("quorum ack: durable=%v err=%v, want durable", durable, err)
	}
	if f, _ := hw.Floor(hwID); f != 1 {
		t.Fatalf("floor after quorum = %d, want 1", f)
	}
	// Durable across a single instance's loss: a fresh instance loading the sealed map
	// keeps the quorum-committed floor.
	hw2 := minter.NewHighWater(hw.Sealed())
	if f, _ := hw2.Floor(hwID); f != 1 {
		t.Fatalf("quorum-committed floor lost on instance restart: %d", f)
	}
}

// TestHighWater_LogReconcile_FailClosed: on restart with a suspect sealed value and no
// fresh verified presentation, the signer refuses to mint for that identity — fail
// closed (availability), not a regressed floor; a fresh verified checkpoint reconciles
// it (PCAS-claim-21).
func TestHighWater_LogReconcile_FailClosed(t *testing.T) {
	key := hwSigner(t)
	hw := minter.NewHighWater(map[string]uint64{hwID: 2},
		minter.WithCheckpointKey(key.Public().DER), minter.WithFreshnessBound(50))
	hw.MarkNeedsReconcile(hwID)

	if hw.Ready(hwID) {
		t.Fatal("identity ready before reconcile (should fail closed)")
	}
	if err := hw.SealAdvance(hwID, 3); !errors.Is(err, minter.ErrNotReconciled) {
		t.Fatalf("mint while unreconciled: got %v, want ErrNotReconciled", err)
	}
	// A stale presentation does not reconcile (still fail closed).
	if err := hw.Reconcile(hwCheckpoint(t, key, 5, 10), 200); !errors.Is(err, minter.ErrStalePresentation) {
		t.Fatalf("stale presentation: got %v, want ErrStalePresentation", err)
	}
	if hw.Ready(hwID) {
		t.Fatal("stale presentation reconciled the identity")
	}
	// A fresh, verified checkpoint reconciles and adopts the newest epoch.
	if err := hw.Reconcile(hwCheckpoint(t, key, 5, 180), 200); err != nil {
		t.Fatalf("fresh reconcile: %v", err)
	}
	if !hw.Ready(hwID) {
		t.Fatal("identity still fail-closed after a fresh reconcile")
	}
	if f, _ := hw.Floor(hwID); f != 5 {
		t.Fatalf("reconciled floor = %d, want 5", f)
	}
	if err := hw.SealAdvance(hwID, 6); err != nil {
		t.Fatalf("mint after reconcile: %v", err)
	}
}

// TestHighWater_StaleReplayCannotLower: replaying an older but validly-signed
// checkpoint cannot lower the adopted floor (PCAS-claim-21).
func TestHighWater_StaleReplayCannotLower(t *testing.T) {
	key := hwSigner(t)
	hw := minter.NewHighWater(nil, minter.WithCheckpointKey(key.Public().DER))
	if err := hw.AdoptPresented(hwCheckpoint(t, key, 5, 100)); err != nil {
		t.Fatal(err)
	}
	if err := hw.AdoptPresented(hwCheckpoint(t, key, 3, 90)); err != nil {
		t.Fatalf("stale replay errored: %v", err)
	}
	if f, _ := hw.Floor(hwID); f != 5 {
		t.Fatalf("floor lowered by stale replay to %d, want 5", f)
	}
}

// TestHighWater_RejectsForgedCheckpoint: a fabricated "newer" checkpoint signed by the
// wrong key is rejected — the control plane can withhold but cannot fabricate (AC5,
// TestSigner_ForgeResistance shape).
func TestHighWater_RejectsForgedCheckpoint(t *testing.T) {
	key := hwSigner(t)
	forger := hwSigner(t)
	hw := minter.NewHighWater(nil, minter.WithCheckpointKey(key.Public().DER), minter.WithFreshnessBound(50))
	forged := hwCheckpoint(t, forger, 99, 100) // signed by the wrong key

	if err := hw.AdoptPresented(forged); !errors.Is(err, minter.ErrCheckpointUnverified) {
		t.Fatalf("adopt forged: got %v, want ErrCheckpointUnverified", err)
	}
	if err := hw.Reconcile(forged, 100); !errors.Is(err, minter.ErrCheckpointUnverified) {
		t.Fatalf("reconcile forged: got %v, want ErrCheckpointUnverified", err)
	}
	if f, _ := hw.Floor(hwID); f != 0 {
		t.Fatalf("forged checkpoint moved the floor to %d", f)
	}
}
