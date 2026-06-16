package projections_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/events"
)

// TestWalkingSkeleton proves the whole spine end-to-end: a RegisterTenant
// command emits an event, the projection updates the read model, and a read
// returns the result — all through the real PostgreSQL + embedded NATS spine,
// not mocks. It lives here to reuse this package's embedded-postgres TestMain.
func TestWalkingSkeleton(t *testing.T) {
	s := newStore(t)  // real PostgreSQL (TestMain) + Migrate + truncate
	log := openLog(t) // embedded NATS JetStream
	ctx := context.Background()
	svc := app.New(log, s)
	defer svc.Close()

	const id = tenantA
	if err := svc.RegisterTenant(ctx, id, "Acme", "skeleton-key"); err != nil {
		t.Fatalf("RegisterTenant: %v", err)
	}

	// 1) the command emitted an event
	emitted := 0
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type == "tenant.registered" && e.TenantID == id {
			emitted++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if emitted != 1 {
		t.Errorf("expected exactly 1 tenant.registered event, got %d", emitted)
	}

	// 2) the projection updated the read model
	tenants, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0].TenantID != id || tenants[0].Name != "Acme" {
		t.Fatalf("read model = %v, want a single Acme tenant", tenants)
	}

	// 3) a read returns the result
	got, err := svc.GetTenant(ctx, id)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.TenantID != id || got.Name != "Acme" {
		t.Errorf("GetTenant = %+v, want the Acme tenant", got)
	}
}

// TestRegisterTenantProjectsOnlyAppendedEvent is the SPINE-008 regression: the
// bootstrap command (now wired into the served RunTokenCreate on-ramp) must
// project ONLY the event it just appended, not replay the whole log inside its
// idempotency transaction. The old shape (proj.Project) re-applied every prior
// event on every call — an O(total-log) write-path footgun.
//
// We prove the new behavior by pre-seeding the log with other-tenant
// tenant.registered events that the read model has NOT yet caught up to, then
// running RegisterTenant. If RegisterTenant did a full replay, those pre-seeded
// tenants would land in the read model as a side effect; with proj.Apply on the
// single appended event, they stay un-projected. The test must FAIL pre-fix (the
// pre-seeded tenants appear) and PASS post-fix.
func TestRegisterTenantProjectsOnlyAppendedEvent(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()

	// Pre-seed the log with events for OTHER tenants, appended out of band (not
	// projected). These are exactly what a full replay would sweep into the read
	// model.
	seeded := []string{
		"33333333-3333-3333-3333-333333333333",
		"44444444-4444-4444-4444-444444444444",
		"55555555-5555-5555-5555-555555555555",
	}
	for _, tid := range seeded {
		if _, err := log.Append(ctx, events.Event{
			Type: "tenant.registered", TenantID: tid, Data: tenantRegistered("seeded-" + tid),
		}); err != nil {
			t.Fatalf("seed append: %v", err)
		}
	}

	svc := app.New(log, s)
	defer svc.Close()
	const id = tenantA
	if err := svc.RegisterTenant(ctx, id, "Acme", "spine008-key"); err != nil {
		t.Fatalf("RegisterTenant: %v", err)
	}

	tenants, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0].TenantID != id {
		t.Fatalf("RegisterTenant projected %d tenants %v; want exactly the one it appended (no full-log replay) — SPINE-008",
			len(tenants), tenants)
	}
}
