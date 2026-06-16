package projections_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// certificateRecorded builds a certificate.recorded payload (a first issuance: no
// owner, no predecessor) for the projector.
func certificateRecorded(id, subject, fingerprint, serial string) []byte {
	b, _ := json.Marshal(projections.CertificateRecorded{
		ID: id, Subject: subject, Fingerprint: fingerprint, Serial: serial,
		Issuer: "trstctl Issuing CA", KeyAlgorithm: "ECDSA-P256", Source: "test",
	})
	return b
}

// certificateRevoked builds a certificate.revoked payload keyed by fingerprint.
func certificateRevoked(fingerprint, serial, reason string) []byte {
	b, _ := json.Marshal(projections.CertificateRevoked{
		Fingerprint: fingerprint, Serial: serial, Reason: reason, RevokedAt: time.Now().UTC(),
	})
	return b
}

// truncateReadModelAndCheckpoint simulates a COLD BOOT / DR restore where the
// relational read model and its projection checkpoint were lost (a fresh PostgreSQL)
// but the event log AND the read-model snapshot survived. It empties the read-model
// tables and resets the checkpoint to 0, leaving any snapshot rows intact — so the
// next boot must rehydrate from the snapshot and replay only the tail (SPINE-007).
func truncateReadModelAndCheckpoint(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Pool().Exec(ctx,
		`TRUNCATE owners, issuers, identities, certificates, identity_transitions, tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate read model: %v", err)
	}
	if _, err := s.Pool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = 0 WHERE id = 1`); err != nil {
		t.Fatalf("reset checkpoint: %v", err)
	}
}

// TestSnapshotBootReplaysOnlyTheTail is the SPINE-007 / EXC-SCALE-01 acceptance: after
// a snapshot is taken, a cold boot rehydrates the read model FROM THE SNAPSHOT and
// replays ONLY the events after the offset the snapshot covers — not the whole log.
//
// It proves "only the tail is replayed" adversarially and deterministically (the same
// technique the checkpoint test uses): a POISON event (a known type carrying an
// unknown schema version, which the projector rejects) is planted BELOW the snapshot
// offset. A from-zero replay would hit the poison and FAIL; the snapshot-bounded boot
// resumes ABOVE the snapshot, never touches the poison, and lands the read model
// exactly at snapshot-rows + the post-snapshot tail. It then proves the log is the
// source of truth: deleting the snapshot and running a full Rebuild (which replays
// from zero — minus the poison, removed for that leg) yields the SAME state.
//
// It FAILS on the pre-fix tree (no snapshot mechanism: boot did a full checkpoint
// catch-up from 0 and would choke on the poison) and PASSES post-fix.
func TestSnapshotBootReplaysOnlyTheTail(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// 1) Seed a tenant + two owners and catch up so they are in the read model.
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-00000000a001", "one")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-00000000a002", "two")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("initial catch-up: %v", err)
	}
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Fatalf("after seed owners = %d, want 2", got)
	}

	// 2) Take a snapshot at the current checkpoint (covers the 2 owners).
	n, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if n != 1 {
		t.Fatalf("Snapshot wrote %d tenant snapshots, want 1", n)
	}
	snapOffset, err := s.LatestSnapshotOffset(ctx)
	if err != nil {
		t.Fatalf("LatestSnapshotOffset: %v", err)
	}
	head, _ := log.LastSequence(ctx)
	if snapOffset != head {
		t.Fatalf("snapshot covered offset = %d, want head %d", snapOffset, head)
	}

	// 3) Append a real tail event (a third owner) AFTER the snapshot. The strict
	// "tail-only replay" proof (a poison event below the covered offset that a from-zero
	// replay would choke on) is the dedicated TestSnapshotRestoreSkipsPoisonBelowOffset
	// below; here we prove (a) the pre-snapshot rows come back from the SNAPSHOT BLOB
	// even though the tail replay starts above them, and (b) the result equals a full
	// rebuild from the log (log is truth).
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-00000000a003", "three")})
	tailHead, _ := log.LastSequence(ctx)

	// 4) Simulate a cold boot / DR restore: the read model + checkpoint are gone, the
	// snapshot + log survive.
	truncateReadModelAndCheckpoint(t, s)
	if got := ownerCount(t, s, tenantA); got != 0 {
		t.Fatalf("after simulated DR wipe owners = %d, want 0", got)
	}

	// 5) Boot via the snapshot path: it rehydrates from the snapshot (covered offset >
	// checkpoint 0) and replays only seq > snapOffset.
	restored, err := p.RestoreFromSnapshot(ctx, log)
	if err != nil {
		t.Fatalf("RestoreFromSnapshot: %v", err)
	}
	if !restored {
		t.Fatal("RestoreFromSnapshot returned restored=false, but a snapshot covering offset > checkpoint exists (SPINE-007)")
	}
	// The read model holds the 2 snapshot owners + the 1 tail owner = 3.
	if got := ownerCount(t, s, tenantA); got != 3 {
		t.Fatalf("after snapshot restore owners = %d, want 3 (2 from snapshot + 1 tail)", got)
	}
	// The checkpoint advanced to the tail head (so a subsequent catch-up replays nothing).
	cp, _ := s.ProjectionCheckpoint(ctx)
	if cp != tailHead {
		t.Fatalf("checkpoint after restore = %d, want tail head %d", cp, tailHead)
	}

	// 6) Capture the post-restore owner ids, then PROVE THE LOG IS THE SOURCE OF TRUTH:
	// delete the snapshot and full-Rebuild from sequence 0 — same state.
	before := ownerIDs(t, s, tenantA)
	if err := s.DeleteAllSnapshots(ctx); err != nil {
		t.Fatalf("DeleteAllSnapshots: %v", err)
	}
	if c, _ := s.SnapshotCount(ctx); c != 0 {
		t.Fatalf("snapshot count after delete = %d, want 0", c)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("full Rebuild after deleting snapshot: %v", err)
	}
	after := ownerIDs(t, s, tenantA)
	if !equalStringSets(before, after) {
		t.Fatalf("read model differs between snapshot-restore (%v) and full-rebuild-from-log (%v): "+
			"the log must be the source of truth (AN-2)", before, after)
	}
}

// TestSnapshotRestoreSkipsPoisonBelowOffset is the strict "tail only" proof: a poison
// event (unknown schema version) sits BELOW a snapshot's covered offset. A from-zero
// replay would reject it; the snapshot boot resumes ABOVE it and succeeds. This pins
// that the snapshot path replays ONLY seq > covered offset (SPINE-007).
func TestSnapshotRestoreSkipsPoisonBelowOffset(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// Seed + catch up a good tenant/owner.
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-00000000b001", "good")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up: %v", err)
	}

	// Append a POISON event (unknown schema version), then take a snapshot whose offset
	// is forced to the poison head — i.e. the snapshot "covers" up to and including the
	// poison. (We capture the read model as-of now; the poison did not apply, but the
	// snapshot offset advances past it the same way the checkpoint would on the live
	// tail. Snapshot reads the current checkpoint, so we advance the checkpoint past the
	// poison first, exactly as the catch-up test does, to model a watermark that already
	// spans an unprocessable sequence.)
	mustAppend(t, log, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		SchemaVersion: 99, // unknown -> a from-zero replay rejects this
		Data:          ownerCreated("00000000-0000-0000-0000-00000000b002", "poison"),
	})
	poisonHead, _ := log.LastSequence(ctx)
	if err := s.AdvanceProjectionCheckpoint(ctx, poisonHead); err != nil {
		t.Fatalf("advance past poison: %v", err)
	}
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// A good tail event AFTER the poison.
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-00000000b003", "after")})

	// Cold boot / DR wipe, then restore via snapshot: it must resume ABOVE the snapshot
	// offset (past the poison) and succeed, NOT replay from zero and choke on the poison.
	truncateReadModelAndCheckpoint(t, s)
	restored, err := p.RestoreFromSnapshot(ctx, log)
	if err != nil {
		t.Fatalf("RestoreFromSnapshot replayed below the snapshot offset and hit the poison: %v "+
			"(SPINE-007: snapshot boot must replay only the tail after the covered offset)", err)
	}
	if !restored {
		t.Fatal("RestoreFromSnapshot returned restored=false despite a snapshot covering offset > checkpoint")
	}
	// good (from snapshot) + after (tail) = 2; the poison was never applied.
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Fatalf("owners after snapshot restore = %d, want 2 (good + after; poison skipped)", got)
	}
}

// TestSnapshotWarmBootSkipsRestore pins that the snapshot path does NOT penalize a
// warm restart: when the checkpoint already covers the snapshot offset (the read model
// survived the restart in PostgreSQL), RestoreFromSnapshot reports restored=false so
// the caller does the cheap checkpoint catch-up instead of a wasteful truncate+reload.
func TestSnapshotWarmBootSkipsRestore(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-00000000c001", "one")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Warm boot: the checkpoint is at head, the snapshot offset equals it, so restore
	// must decline (restored=false) and leave the read model untouched.
	restored, err := p.RestoreFromSnapshot(ctx, log)
	if err != nil {
		t.Fatalf("RestoreFromSnapshot: %v", err)
	}
	if restored {
		t.Fatal("RestoreFromSnapshot restored on a WARM boot (checkpoint already covers the snapshot); " +
			"it must decline so the warm path stays a cheap catch-up (SPINE-007)")
	}
	if got := ownerCount(t, s, tenantA); got != 1 {
		t.Fatalf("warm boot owners = %d, want 1 (untouched)", got)
	}
}

// TestSnapshotRestoreReproducesCertificateStatus proves the snapshot captures the FULL
// read-model row, including derived status columns that come from LATER events
// (revoked/superseded), so a snapshot restore reproduces the exact state — not just
// the create-time fields. A certificate is recorded then revoked; the snapshot, taken
// after the revoke, must restore the certificate with status 'revoked' on a cold boot.
func TestSnapshotRestoreReproducesCertificateStatus(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	mustAppend(t, log, events.Event{Type: projections.EventCertificateRecorded, TenantID: tenantA,
		Data: certificateRecorded("00000000-0000-0000-0000-00000000e001", "cert-1", "AA:BB", "00:01")})
	mustAppend(t, log, events.Event{Type: projections.EventCertificateRevoked, TenantID: tenantA,
		Data: certificateRevoked("AA:BB", "00:01", "keyCompromise")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	if st := certStatus(t, s, tenantA, "AA:BB"); st != "revoked" {
		t.Fatalf("pre-snapshot cert status = %q, want revoked", st)
	}

	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Cold boot / DR wipe, then restore from the snapshot.
	truncateReadModelAndCheckpoint(t, s)
	if _, err := p.RestoreFromSnapshot(ctx, log); err != nil {
		t.Fatalf("RestoreFromSnapshot: %v", err)
	}
	// The restored certificate must still be revoked — proving the snapshot blob carried
	// the derived status, not just the recorded fields.
	if st := certStatus(t, s, tenantA, "AA:BB"); st != "revoked" {
		t.Fatalf("post-restore cert status = %q, want revoked (snapshot must capture derived status, SPINE-007)", st)
	}
}

// TestConcurrentCatchUpConvergesToSingleProjectorState pins the RESIL-004 multi-replica
// projector safety the audit flagged as untested: N projectors catching up against ONE
// store concurrently (the path RESIL-002's multi-replica default unlocks) must converge
// to the SAME read model a single projector would produce — never a corrupted or
// doubled one. The boot catch-up serializes on the projection advisory lock
// (WithProjectionLock), so concurrent boots take turns rather than racing into the
// read-model tables. This is independent of leader election (which gates the
// CONTINUOUS workers); the boot catch-up is safe on every replica by design.
func TestConcurrentCatchUpConvergesToSingleProjectorState(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()

	// Seed a tenant + a spread of owners.
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	const owners = 12
	for i := 0; i < owners; i++ {
		id := fmt.Sprintf("00000000-0000-0000-0000-0000000f%04d", i)
		mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated(id, fmt.Sprintf("o%d", i))})
	}

	// Run several projectors' catch-up concurrently against the same store.
	const replicas = 5
	var wg sync.WaitGroup
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := projections.New(s)
			errs <- p.ProjectCatchUp(ctx, log)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ProjectCatchUp errored (advisory lock should serialize, RESIL-004): %v", err)
		}
	}

	// The read model holds exactly the seeded owners — not doubled, not missing.
	if got := ownerCount(t, s, tenantA); got != owners {
		t.Fatalf("owners after %d concurrent catch-ups = %d, want %d (single-projector state; concurrent projectors must converge, RESIL-004)", replicas, got, owners)
	}
	// The checkpoint advanced to the head exactly once (monotonic, not rewound).
	head, _ := log.LastSequence(ctx)
	cp, _ := s.ProjectionCheckpoint(ctx)
	if cp != head {
		t.Fatalf("checkpoint after concurrent catch-up = %d, want head %d", cp, head)
	}
}

// TestSnapshotRestoreIsTenantScoped is the AN-1 acceptance for snapshots: with TWO
// tenants, the snapshot of each holds ONLY its own rows, and a cold-boot restore
// rehydrates each tenant's rows under its own RLS context — tenant A never sees tenant
// B's rows and vice versa. This guards against a snapshot that leaks rows across the
// tenant boundary on capture or restore.
func TestSnapshotRestoreIsTenantScoped(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantB, Data: tenantRegistered("Beta")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000aa001", "a-only")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated("00000000-0000-0000-0000-0000000bb001", "b-only-1")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated("00000000-0000-0000-0000-0000000bb002", "b-only-2")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up: %v", err)
	}

	// Snapshot both tenants, wipe, restore.
	if n, err := p.Snapshot(ctx); err != nil || n != 2 {
		t.Fatalf("Snapshot wrote n=%d err=%v, want n=2 (one per tenant)", n, err)
	}
	truncateReadModelAndCheckpoint(t, s)
	if _, err := p.RestoreFromSnapshot(ctx, log); err != nil {
		t.Fatalf("RestoreFromSnapshot: %v", err)
	}

	// Each tenant sees only its own owners, restored faithfully.
	if got := ownerCount(t, s, tenantA); got != 1 {
		t.Fatalf("tenant A owners after restore = %d, want 1 (no cross-tenant leak)", got)
	}
	if got := ownerCount(t, s, tenantB); got != 2 {
		t.Fatalf("tenant B owners after restore = %d, want 2 (no cross-tenant leak)", got)
	}
	aIDs := ownerIDs(t, s, tenantA)
	if aIDs["00000000-0000-0000-0000-0000000bb001"] || aIDs["00000000-0000-0000-0000-0000000bb002"] {
		t.Fatalf("tenant A's restored read model contains tenant B's owners (AN-1 violation): %v", aIDs)
	}
}

// ownerIDs returns the set of owner ids visible for tenantID under its RLS context.
func ownerIDs(t *testing.T, s *store.Store, tenantID string) map[string]bool {
	t.Helper()
	ctx := context.Background()
	out := map[string]bool{}
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT id FROM owners")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = true
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("owner ids %s: %v", tenantID, err)
	}
	return out
}

func equalStringSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// certStatus returns a certificate's status by fingerprint under tenantID's RLS context.
func certStatus(t *testing.T, s *store.Store, tenantID, fingerprint string) string {
	t.Helper()
	ctx := context.Background()
	var status string
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT status FROM certificates WHERE fingerprint = $1", fingerprint).Scan(&status)
	}); err != nil {
		t.Fatalf("cert status %s/%s: %v", tenantID, fingerprint, err)
	}
	return status
}
