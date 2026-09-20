// SPDX-License-Identifier: BUSL-1.1

package minter_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/minter"
)

func hsmMinter(t *testing.T) (*minter.Minter, *minter.SoftHSM) {
	t.Helper()
	hsm := minter.NewSoftHSM(crypto.NewSoftwareBackend())
	pred, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	hsm.Import("pred", pred)
	m, err := minter.New(hsm, hsm, hsm.FloorStore())
	if err != nil {
		t.Fatal(err)
	}
	return m, hsm
}

// TestHSM_CustodyBoundaryNoRelease: private key material is never released from the
// custody boundary — an export attempt fails closed, and a mint over the HSM backend
// still yields a verifiable record carrying only public material (PCAS-claim-26 / INV-1).
func TestHSM_CustodyBoundaryNoRelease(t *testing.T) {
	hsm := minter.NewSoftHSM(crypto.NewSoftwareBackend())
	s, err := hsm.GenerateKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	// The handle signs and exposes a public key, but nothing exports the private key.
	if _, err := s.Sign([]byte("msg"), crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("in-boundary sign: %v", err)
	}
	if len(s.Public().DER) == 0 {
		t.Fatal("no public key from the boundary handle")
	}
	if _, err := hsm.TryExport("hsm-1"); !errors.Is(err, minter.ErrKeyMaterialNotReleasable) {
		t.Fatalf("export attempt: got %v, want ErrKeyMaterialNotReleasable", err)
	}

	// A mint over the HSM backend produces a verifiable record; only public material
	// crossed the boundary.
	m, mhsm := hsmMinter(t)
	if _, err := mhsm.TryExport("pred"); !errors.Is(err, minter.ErrKeyMaterialNotReleasable) {
		t.Fatalf("predecessor export attempt: got %v, want ErrKeyMaterialNotReleasable", err)
	}
	res, err := m.MintSuccessor(ctx, baseReq())
	if err != nil {
		t.Fatalf("hsm mint: %v", err)
	}
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := succession.VerifyRecord(rec); err != nil {
		t.Fatalf("hsm-minted record does not verify: %v", err)
	}
}

// TestHSM_HighWaterWithinBoundary: the epoch floor lives within the module — a fresh
// signer process (control-plane reset/rollback) loads the authoritative floor from
// the module and refuses a mint below it (PCAS-claim-26 / INV-3).
func TestHSM_HighWaterWithinBoundary(t *testing.T) {
	m1, hsm := hsmMinter(t)

	if _, err := m1.MintSuccessor(ctx, baseReq()); err != nil {
		t.Fatalf("first hsm mint: %v", err)
	}
	if f := hsm.ModuleFloor(baseReq().IdentityID); f != 1 {
		t.Fatalf("module-resident floor = %d, want 1", f)
	}

	// Control-plane reset/rollback: a brand-new Minter over the SAME module. Its
	// in-memory floor is empty, but it loads the authoritative floor from the module.
	m2, err := minter.New(hsm, hsm, hsm.FloorStore())
	if err != nil {
		t.Fatal(err)
	}
	// A mint below the module floor (asserted 0, floor 1) is refused BY THE BOUNDARY.
	if _, err := m2.MintSuccessor(ctx, baseReq()); !errors.Is(err, minter.ErrEpochNotCurrent) {
		t.Fatalf("mint below module floor: got %v, want ErrEpochNotCurrent", err)
	}
	// Minting at the module floor advances it (asserted 1 → epoch 2).
	cur := baseReq()
	cur.AssertedPredecessorEpoch = 1
	res, err := m2.MintSuccessor(ctx, cur)
	if err != nil {
		t.Fatalf("mint at module floor: %v", err)
	}
	if res.Epoch != 2 {
		t.Fatalf("epoch = %d, want 2", res.Epoch)
	}
	if f := hsm.ModuleFloor(baseReq().IdentityID); f != 2 {
		t.Fatalf("module floor after advance = %d, want 2", f)
	}
}
