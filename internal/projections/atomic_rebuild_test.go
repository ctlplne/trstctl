// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// This test reuses the shared package helpers ownerCreated(id, name) and
// ownerCount(t, s, tenantID) defined alongside the other projections tests.

// TestRebuildIsAtomicOnMidReplayFailure keeps the prior read model intact when
// a tenant lifecycle schema cannot be projected during a full rebuild.
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

	// Lifecycle history has its own fail-closed schema contract. Its refusal
	// must roll back the entire rebuild transaction.
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		SchemaVersion: 99,
		Data:          tenantRegistered("Updated tenant"),
	}); err != nil {
		t.Fatal(err)
	}

	// A rebuild must refuse the unsupported lifecycle schema.
	if err := p.Rebuild(ctx, log); err == nil {
		t.Fatal("Rebuild accepted an unsupported lifecycle schema")
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
