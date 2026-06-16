package projections_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// ownerCreated builds an owner.created payload for the projector.
func ownerCreated(id, name string) []byte {
	b, _ := json.Marshal(projections.OwnerCreated{ID: id, Kind: "Service", Name: name})
	return b
}

// ownerCount returns the number of owners visible for tenantID under its RLS context.
func ownerCount(t *testing.T, s *store.Store, tenantID string) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM owners").Scan(&n)
	}); err != nil {
		t.Fatalf("count owners %s: %v", tenantID, err)
	}
	return n
}

// TestTenantOffboardedEventErasesAndSurvivesRebuild is the AN-2 half of TENANT-002:
// a tenant.offboarded event drives the projector to erase the tenant's rows, and —
// because the erase is event-sourced — a Rebuild from the log reproduces the
// erased state rather than resurrecting the tenant. Tenant B (no offboard event)
// is untouched throughout.
func TestTenantOffboardedEventErasesAndSurvivesRebuild(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// Register both tenants and give each an owner (all via the event log).
	for _, tc := range []struct{ id, name string }{{tenantA, "Acme"}, {tenantB, "Beta"}} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tc.id, Data: tenantRegistered(tc.name)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("aaaaaaaa-0000-0000-0000-000000000001", "owner-a")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated("bbbbbbbb-0000-0000-0000-000000000001", "owner-b")}); err != nil {
		t.Fatal(err)
	}
	if err := p.Project(ctx, log); err != nil {
		t.Fatalf("project: %v", err)
	}
	if ownerCount(t, s, tenantA) != 1 || ownerCount(t, s, tenantB) != 1 {
		t.Fatalf("precondition: each tenant should have 1 owner (A=%d B=%d)", ownerCount(t, s, tenantA), ownerCount(t, s, tenantB))
	}

	// Offboard A via an event, then project it.
	off, _ := json.Marshal(struct {
		RowsDeleted int `json:"rows_deleted"`
	}{2})
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantOffboarded, TenantID: tenantA, Data: off}); err != nil {
		t.Fatal(err)
	}
	if err := p.Project(ctx, log); err != nil {
		t.Fatalf("project offboard: %v", err)
	}

	// A is erased; B intact; A's tenant row gone.
	if got := ownerCount(t, s, tenantA); got != 0 {
		t.Errorf("after offboard event, tenant A owners = %d, want 0", got)
	}
	if got := ownerCount(t, s, tenantB); got != 1 {
		t.Errorf("tenant B owners changed by A's offboard: %d, want 1", got)
	}
	if _, err := s.GetTenant(ctx, tenantA); !store.IsNotFound(err) {
		t.Errorf("tenant A's row should be gone after the offboard event; err = %v", err)
	}

	// AN-2: a full Rebuild from the log reproduces the erased state — the offboard
	// event replays, so the tenant is NOT resurrected.
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if got := ownerCount(t, s, tenantA); got != 0 {
		t.Errorf("after Rebuild, tenant A owners = %d, want 0 (offboard must replay, not resurrect)", got)
	}
	if got := ownerCount(t, s, tenantB); got != 1 {
		t.Errorf("after Rebuild, tenant B owners = %d, want 1", got)
	}
	tenants, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range tenants {
		if tn.TenantID == tenantA {
			t.Errorf("after Rebuild, tenant A was resurrected in the read model: %+v", tn)
		}
	}
}
