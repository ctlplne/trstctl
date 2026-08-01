// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator_test

import (
	"context"
	"testing"

	pcasstore "trstctl.com/trstctl/ee/succession/store"

	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/ee/succession/orchestrator"
	"trstctl.com/trstctl/internal/crypto"
	corestore "trstctl.com/trstctl/internal/store"
)

// TestCrashRecovery_ExactlyOnce: a succession minted under an idempotency key, then
// retried after a signer/orchestrator restart (a fresh process over the SAME durable
// store), is not re-minted — the recorded record replays and exactly one record + one
// outbox row exist (PCAS-claim-6 / INV-4, the crash-recovery limb, PCAS-12).
func TestCrashRecovery_ExactlyOnce(t *testing.T) {
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	be := crypto.NewSoftwareBackend()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	const key = "crash-key-1"
	id := "spiffe://d/crash"

	// Instance 1 mints and records under the idempotency key.
	m1, err := minter.New(mapResolver{"pred": pred}, be, newMemFloor())
	if err != nil {
		t.Fatal(err)
	}
	cm1 := &countingMinter{inner: m1}
	orch1 := orchestrator.New(cs, cm1)
	r1, err := orch1.RunSuccession(ctx, tenantA, req(id), key)
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if r1.Replayed || r1.Epoch != 1 {
		t.Fatalf("run 1: replayed=%v epoch=%d, want false,1", r1.Replayed, r1.Epoch)
	}

	// "Crash + restart": a brand-new signer + orchestrator (fresh floor) over the SAME
	// durable store. The retry with the same key replays — it does NOT mint again.
	m2, err := minter.New(mapResolver{"pred": pred}, be, newMemFloor())
	if err != nil {
		t.Fatal(err)
	}
	cm2 := &countingMinter{inner: m2}
	orch2 := orchestrator.New(cs, cm2)
	r2, err := orch2.RunSuccession(ctx, tenantA, req(id), key)
	if err != nil {
		t.Fatalf("run 2 (post-restart): %v", err)
	}
	if !r2.Replayed {
		t.Fatal("post-restart retry re-minted instead of replaying")
	}
	if cm2.calls != 0 {
		t.Fatalf("post-restart minter was called %d times, want 0 (exactly-once)", cm2.calls)
	}
	if string(r1.Record) != string(r2.Record) {
		t.Fatal("post-restart replay returned a different record")
	}

	// Exactly one succession row and one outbox row for the key.
	var recs, outbox int
	if err := cs.SystemPool().QueryRow(ctx, `SELECT count(*) FROM succession_records WHERE identity_id=$1`, id).Scan(&recs); err != nil {
		t.Fatal(err)
	}
	if err := cs.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE idempotency_key=$1`, key).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if recs != 1 || outbox != 1 {
		t.Fatalf("rows = %d succession, %d outbox; want 1, 1 (exactly-once)", recs, outbox)
	}
}
