package projections_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// This test reuses the shared package helpers ownerCreated(id, name) and
// ownerCount(t, s, tenantID) defined alongside the other projections tests.

// TestRebuildIsAtomicOnMidReplayFailure is the RESIL-003 acceptance: if a rebuild
// fails partway through replaying the log, the read model must be left fully in its
// pre-rebuild state, never truncated/partial. On the pre-fix tree Rebuild truncated
// in its own auto-committed statement and then replayed event-by-event, so a
// mid-replay failure left the inventory empty while the API could still answer
// queries. Here a poison event (a known type carrying an unknown schema version)
// makes the replay fail mid-stream, and we assert the prior read model survived.
func TestRebuildIsAtomicOnMidReplayFailure(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// Build a populated read model: a tenant + two owners.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000a1", "alpha")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000a2", "beta")}); err != nil {
		t.Fatal(err)
	}
	if err := p.Project(ctx, log); err != nil {
		t.Fatalf("initial project: %v", err)
	}
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Fatalf("pre-rebuild owners = %d, want 2", got)
	}

	// Append a poison event AFTER the good ones: a known type (owner.created) carrying
	// a schema version the projector does not understand, so ApplyTx rejects it
	// (ErrUnknownSchemaVersion) partway through a full replay.
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		SchemaVersion: 99, // unknown -> ApplyTx fails
		Data:          ownerCreated("00000000-0000-0000-0000-0000000000a3", "poison"),
	}); err != nil {
		t.Fatal(err)
	}

	// A rebuild must now fail (the poison event aborts the replay)...
	if err := p.Rebuild(ctx, log); err == nil {
		t.Fatal("Rebuild succeeded despite a poison event; expected a replay failure")
	}

	// ...and because the rebuild is atomic, the read model must be UNCHANGED — still
	// the two pre-rebuild owners, NOT empty and NOT a partial subset.
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Fatalf("after failed rebuild owners = %d, want 2 (atomic rebuild must roll back to the prior state, never leave it empty/partial)", got)
	}
	// The tenant row must also survive (the whole read model rolled back as a unit).
	tn, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tn) != 1 {
		t.Fatalf("after failed rebuild tenants = %d, want 1", len(tn))
	}
}

// TestRebuildAtomicReproducesStateOnSuccess proves the atomic rebuild still produces
// the correct read model on the happy path (the truncate+replay-in-one-transaction
// change did not break normal rebuild), including a tenant.registered + owners
// round-trip.
func TestRebuildAtomicReproducesStateOnSuccess(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}
	for _, o := range []struct{ id, name string }{
		{"00000000-0000-0000-0000-0000000000b1", "one"},
		{"00000000-0000-0000-0000-0000000000b2", "two"},
		{"00000000-0000-0000-0000-0000000000b3", "three"},
	} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated(o.id, o.name)}); err != nil {
			t.Fatal(err)
		}
	}
	// Dirty the read model first so the rebuild has something to discard.
	if err := p.Project(ctx, log); err != nil {
		t.Fatalf("project: %v", err)
	}

	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("atomic Rebuild: %v", err)
	}
	if got := ownerCount(t, s, tenantA); got != 3 {
		t.Fatalf("after rebuild owners = %d, want 3", got)
	}
}
