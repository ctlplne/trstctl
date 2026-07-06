// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestDurableFloorStore_PersistsAndIsMonotonic: advances persist across a fresh store
// opened on the same directory (restart), and a lower-or-equal epoch never regresses
// the stored floor.
func TestDurableFloorStore_PersistsAndIsMonotonic(t *testing.T) {
	dir := t.TempDir()
	s1, err := minter.NewDurableFloorStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Advance("id-a", 3); err != nil {
		t.Fatal(err)
	}
	if err := s1.Advance("id-a", 2); err != nil { // monotonic: no-op, must not regress
		t.Fatal(err)
	}
	if err := s1.Advance("id-b", 1); err != nil {
		t.Fatal(err)
	}

	s2, err := minter.NewDurableFloorStore(dir) // fresh store over the same dir = restart
	if err != nil {
		t.Fatal(err)
	}
	m, err := s2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if m["id-a"] != 3 || m["id-b"] != 1 {
		t.Fatalf("reloaded floors = %v, want id-a=3 id-b=1", m)
	}
}

type floorTestResolver map[string]crypto.Signer

func (r floorTestResolver) Resolve(h string) (crypto.Signer, error) {
	s, ok := r[h]
	if !ok {
		return nil, errors.New("no handle")
	}
	return s, nil
}

// TestINT05_DurableFloorRefusesStaleEpochAfterRestart proves the durable floor
// survives a signer restart (claim 21): minter 1 mints epoch 1 over a durable floor;
// a FRESH minter + fresh floor store over the SAME directory loads floor=1 and refuses
// the stale asserted-epoch-0 mint. With an in-memory floor the fresh minter would
// re-mint at epoch 1 — a rollback.
func TestINT05_DurableFloorRefusesStaleEpochAfterRestart(t *testing.T) {
	dir := t.TempDir()
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	res := floorTestResolver{"pred": pred}
	req := signing.MintRequest{
		IdentityID: "spiffe://d/int05", TenantID: "t", DeploymentScope: "d",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: "p",
	}

	f1, err := minter.NewDurableFloorStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := minter.New(res, be, f1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m1.MintSuccessor(context.Background(), req); err != nil {
		t.Fatalf("mint epoch 1: %v", err)
	}

	// "Restart": fresh minter + fresh floor store over the SAME dir.
	f2, err := minter.NewDurableFloorStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := minter.New(res, be, f2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.MintSuccessor(context.Background(), req); !errors.Is(err, minter.ErrEpochNotCurrent) {
		t.Fatalf("post-restart stale mint err = %v, want ErrEpochNotCurrent", err)
	}
}
