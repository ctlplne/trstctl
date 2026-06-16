package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// ownerCreatedPayload is the v1 owner.created payload shape (mirrors
// projections.OwnerCreated). The SCHEMA-001 tests use it as the "old" payload an
// existing-but-evolved type would replace.
func ownerCreatedPayload(id, name string) []byte {
	b, _ := json.Marshal(struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}{ID: id, Kind: "workload", Name: name, Email: name + "@example.com"})
	return b
}

// TestReplayOldEventsNewProjector is the SCHEMA-001 acceptance: a stream of
// version-1 events (the "old" payload shape) still projects and rebuilds
// correctly under the current projector, AND an event of a *known* type carrying a
// schema version the projector does not understand is rejected with a hard error
// rather than silently decoded against the wrong struct.
//
// This is the failure the schema-version field exists to catch: when an existing
// type's payload shape changes, the new events must declare a new version so a
// replay/rebuild can tell them apart from the old ones. Without the gate, a
// shape-changed payload would lenient-decode into the old struct and produce a
// wrong read model with no error on the most load-bearing (DR/rebuild) path.
func TestReplayOldEventsNewProjector(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// A v1 stream: register the tenant, then create two owners with the baseline
	// (version-1) owner.created payload — exactly what today's command side emits.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreatedPayload("11111111-aaaa-4aaa-8aaa-111111111111", "payments")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreatedPayload("22222222-bbbb-4bbb-8bbb-222222222222", "billing")}); err != nil {
		t.Fatal(err)
	}

	// The old (v1) events project cleanly.
	if err := p.Project(ctx, log); err != nil {
		t.Fatalf("project v1 stream: %v", err)
	}
	owners, err := s.ListOwners(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListOwners: %v", err)
	}
	if len(owners) != 2 {
		t.Fatalf("projected %d owners from the v1 stream, want 2", len(owners))
	}

	// And a Rebuild from the same v1 log reproduces the state (AN-2 / DR path).
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild v1 stream: %v", err)
	}
	owners2, err := s.ListOwners(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners2) != 2 {
		t.Fatalf("rebuild produced %d owners, want 2 (rebuild must reproduce the v1 read model)", len(owners2))
	}

	// Now simulate the dangerous case: a deployment changed owner.created's payload
	// shape and stamped it version 2, but this projector only knows version 1.
	// Appending and replaying such an event MUST fail (so the wrong shape is never
	// applied), not silently mis-project.
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA, SchemaVersion: 2,
		Data: ownerCreatedPayload("33333333-cccc-4ccc-8ccc-333333333333", "shipping"),
	}); err != nil {
		t.Fatal(err)
	}
	err = p.Project(ctx, log)
	if !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("projecting an owner.created v2 (unknown to this projector) err = %v, want ErrUnknownSchemaVersion", err)
	}
}

// TestApplyTxRejectsUnknownVersionForKnownType pins the gate at the ApplyTx unit
// level: a known event type at an unknown version is rejected, while the same
// type at the known version applies (SCHEMA-001).
func TestApplyTxRejectsUnknownVersionForKnownType(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	p := projections.New(s)

	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}

	// Known type, known version (1): applies.
	v1 := events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA, SchemaVersion: 1,
		Data: ownerCreatedPayload("44444444-dddd-4ddd-8ddd-444444444444", "ops"),
	}
	if err := p.Apply(ctx, v1); err != nil {
		t.Fatalf("Apply v1 owner.created: %v", err)
	}

	// Known type, unknown version (99): rejected — the wrong shape must never apply.
	v99 := events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA, SchemaVersion: 99,
		Data: ownerCreatedPayload("55555555-eeee-4eee-8eee-555555555555", "sre"),
	}
	if err := p.Apply(ctx, v99); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("Apply owner.created v99 err = %v, want ErrUnknownSchemaVersion", err)
	}

	// A wholly unknown *type* stays forward-compatible (ignored, not an error),
	// regardless of version — only known types are version-gated.
	unknown := events.Event{Type: "future.event.kind", TenantID: tenantA, SchemaVersion: 7, Data: []byte(`{}`)}
	if err := p.Apply(ctx, unknown); err != nil {
		t.Errorf("Apply of an unknown event type should be ignored, got %v", err)
	}
}
