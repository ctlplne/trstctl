// SPDX-License-Identifier: BUSL-1.1

package minter_test

import (
	"errors"
	"reflect"
	"testing"
	"trstctl.com/trstctl/internal/proptest"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/rpverify"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/minter"
)

// TestFloor_HistoryDeterminationEqualsCounter: the counter-free history floor and
// a stored counter derive the same floor over the same advance sequence (PCAS-claim-48
// / INV-16).
func TestFloor_HistoryDeterminationEqualsCounter(t *testing.T) {
	hist := minter.NewHistoryFloorStore()
	counter := newMemFloor()
	seq := []struct {
		id string
		e  uint64
	}{{"a", 1}, {"b", 1}, {"a", 2}, {"a", 3}, {"b", 2}, {"c", 1}}
	for _, s := range seq {
		if err := hist.Advance(s.id, s.e); err != nil {
			t.Fatal(err)
		}
		if err := counter.Advance(s.id, s.e); err != nil {
			t.Fatal(err)
		}
		hl, _ := hist.Load()
		cl, _ := counter.Load()
		if !reflect.DeepEqual(hl, cl) {
			t.Fatalf("after %+v: history floor %v != counter floor %v", s, hl, cl)
		}
	}
}

// TestCounterFree_RefusesSameRollbacks: a minter using the counter-free history
// floor refuses exactly the requests a stored-counter minter refuses, over a
// random corpus (PCAS-claims-48/49 / INV-16). Any divergence is an automatic RED.
func TestCounterFree_RefusesSameRollbacks(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	mk := func(floor minter.FloorStore) *minter.Minter {
		pred, err := be.GenerateKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		m, err := minter.New(mapResolver{"pred": pred}, be, floor)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	for seed := int64(0); seed < 40; seed++ {
		rng := proptest.New(seed)
		mh := mk(minter.NewHistoryFloorStore())
		mc := mk(newMemFloor())
		for n := 0; n < 20; n++ {
			req := baseReq()
			// Drawn as a uint64 so the epoch is the request's own type end to end:
			// AssertedPredecessorEpoch is a uint64, and 2^64 is a multiple of 4, so
			// the remainder is uniform over [0,4) — a mix of current + rollback/skip.
			req.AssertedPredecessorEpoch = rng.Uint64() % 4
			req.TargetAlgorithm = crypto.ECDSAP384
			_, eh := mh.MintSuccessor(ctx, req)
			_, ec := mc.MintSuccessor(ctx, req)
			if (eh == nil) != (ec == nil) {
				t.Fatalf("seed %d n %d asserted %d: history err=%v vs counter err=%v (modes diverged)", seed, n, req.AssertedPredecessorEpoch, eh, ec)
			}
		}
	}
}

// TestEpoch_DerivedBoundAndEnforced: minting under the derived (history) floor and
// the stored counter binds the same epoch in a verifiable record (PCAS-claim-47).
func TestEpoch_DerivedBoundAndEnforced(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	predH, _ := be.GenerateKey(crypto.ECDSAP256)
	predC, _ := be.GenerateKey(crypto.ECDSAP256)
	mh, _ := minter.New(mapResolver{"pred": predH}, be, minter.NewHistoryFloorStore())
	mc, _ := minter.New(mapResolver{"pred": predC}, be, newMemFloor())
	req := baseReq()
	req.TargetAlgorithm = crypto.ECDSAP384

	rh, eh := mh.MintSuccessor(ctx, req)
	if eh != nil {
		t.Fatal(eh)
	}
	rc, ec := mc.MintSuccessor(ctx, req)
	if ec != nil {
		t.Fatal(ec)
	}
	if rh.Epoch != 1 || rc.Epoch != 1 {
		t.Fatalf("epochs: history %d, counter %d, want 1", rh.Epoch, rc.Epoch)
	}
	recH, _ := minter.DecodeRecord(rh.EncodedRecord)
	recC, _ := minter.DecodeRecord(rc.EncodedRecord)
	if recH.Fields.Epoch != recC.Fields.Epoch {
		t.Fatal("bound epoch differs between derived and stored modes")
	}
	if err := succession.VerifyRecord(recH); err != nil {
		t.Fatalf("derived-mode record does not verify: %v", err)
	}
	if err := succession.VerifyRecord(recC); err != nil {
		t.Fatalf("stored-mode record does not verify: %v", err)
	}
}

// TestCounterAgnostic_MintAndVerify: mint under the counter-free floor, then
// verify offline; a rollback is refused custody-side (independent PCAS-claim-49).
func TestCounterAgnostic_MintAndVerify(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	trustRoot, _ := be.GenerateKey(crypto.ECDSAP256)
	pred, _ := be.GenerateKey(crypto.ECDSAP256)
	m, _ := minter.New(mapResolver{"pred": pred}, be, minter.NewHistoryFloorStore())

	req := baseReq()
	req.IdentityID = "spiffe://td.example/ca"
	req.TargetAlgorithm = crypto.ECDSAP384
	res, err := m.MintSuccessor(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := minter.DecodeRecord(res.EncodedRecord)

	genesis := succession.GenesisRecord{
		DeploymentScope: req.DeploymentScope, IdentityID: req.IdentityID, TenantID: req.TenantID,
		Algorithm: pred.Algorithm(), PublicKey: pred.Public().DER, Epoch: 0,
	}
	gd, _ := succession.GenesisDigest(genesis)
	genesis.TrustRootAtt, _ = trustRoot.Sign(gd, crypto.SignOptions{Hash: crypto.SHA256})

	in := rpverify.Input{TrustRootPubDER: trustRoot.Public().DER, Genesis: genesis, Chain: []succession.SuccessionRecord{rec}}
	if _, err := rpverify.Verify(in, nil, rpverify.Options{ExpectedTenant: req.TenantID}); err != nil {
		t.Fatalf("counter-agnostic offline verify failed: %v", err)
	}
	// Rollback refused custody-side: re-mint at the now-stale asserted epoch 0.
	if _, err := m.MintSuccessor(ctx, req); !errors.Is(err, minter.ErrEpochNotCurrent) {
		t.Fatalf("rollback: got %v, want ErrEpochNotCurrent", err)
	}
}
