package projections_test

import (
	"context"
	"testing"

	"certctl.io/certctl/internal/app"
	"certctl.io/certctl/internal/events"
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
