package projections_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestProjectCatchUpReplaysOnlyAfterCheckpoint is the SPINE-007 acceptance: boot
// catch-up must replay ONLY the events after the persisted projection checkpoint —
// the high-water mark of what the read model has already applied — not re-apply the
// whole log from sequence 0 on every restart.
//
// The proof is adversarial and deterministic: after a first catch-up advances the
// watermark, we append a NEW good event AND retroactively cannot un-apply the
// earlier ones, so instead we verify the watermark moved and a second catch-up
// applies only the tail. To prove the earlier events are genuinely SKIPPED (not
// merely idempotently re-applied), the companion test below plants a poison event
// below the watermark and asserts catch-up does not touch it.
func TestProjectCatchUpReplaysOnlyAfterCheckpoint(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// Seed three owners under a tenant and catch up once.
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	for _, o := range []struct{ id, name string }{
		{"00000000-0000-0000-0000-0000000000c1", "one"},
		{"00000000-0000-0000-0000-0000000000c2", "two"},
	} {
		mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated(o.id, o.name)})
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("first catch-up: %v", err)
	}
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Fatalf("after first catch-up owners = %d, want 2", got)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cp != head {
		t.Fatalf("checkpoint = %d after catch-up, want head %d (watermark must track the applied head)", cp, head)
	}

	// Append one more event and catch up again: only the tail event is applied, and
	// the watermark advances to the new head.
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000c3", "three")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("second catch-up: %v", err)
	}
	if got := ownerCount(t, s, tenantA); got != 3 {
		t.Fatalf("after second catch-up owners = %d, want 3", got)
	}
	newHead, _ := log.LastSequence(ctx)
	cp2, _ := s.ProjectionCheckpoint(ctx)
	if cp2 != newHead {
		t.Fatalf("checkpoint = %d after second catch-up, want new head %d", cp2, newHead)
	}
}

// TestProjectCatchUpSkipsEventsBelowCheckpoint proves catch-up does NOT re-replay
// from sequence 0: a poison event (a known type carrying an unknown schema version,
// which the projector rejects) sits BELOW the watermark. A from-zero replay would
// hit it and fail; the watermark-bounded catch-up skips it entirely. The test must
// FAIL on the pre-fix tree (where boot did proj.Project from 0 and would error on
// the poison event) and PASS post-fix.
func TestProjectCatchUpSkipsEventsBelowCheckpoint(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// A good tenant + owner, caught up so the watermark advances past them.
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000d1", "first")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("initial catch-up: %v", err)
	}

	// Now FORCE the checkpoint forward past a poison sequence by appending a poison
	// event and manually advancing the watermark beyond it, simulating a watermark
	// that already covers a span the projector could not re-process. (In production
	// the poison would never have been checkpointed, but this isolates the "resume,
	// do not restart" guarantee.)
	mustAppend(t, log, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		SchemaVersion: 99, // unknown -> Apply would reject this on a from-zero replay
		Data:          ownerCreated("00000000-0000-0000-0000-0000000000d2", "poison"),
	})
	poisonHead, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, poisonHead); err != nil {
		t.Fatalf("advance past poison: %v", err)
	}

	// A good event AFTER the poison.
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000d3", "after")})

	// Catch-up must succeed: it resumes from the watermark (past the poison), applies
	// only the trailing good event, and never re-touches the poison sequence.
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up re-processed below the watermark and hit the poison event: %v "+
			"(SPINE-007: boot must resume from the checkpoint, not replay from zero)", err)
	}
	// owners: first + after = 2 (the poison was never applied).
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Fatalf("owners = %d, want 2 (first + after; poison skipped)", got)
	}
}

func mustAppend(t *testing.T, log *events.Log, e events.Event) {
	t.Helper()
	if _, err := log.Append(context.Background(), e); err != nil {
		t.Fatalf("append %s: %v", e.Type, err)
	}
}
