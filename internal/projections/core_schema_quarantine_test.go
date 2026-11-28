// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestUnsupportedCoreSchemaConfinesTenantDuringReplay(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	for _, tenant := range []struct{ id, name string }{{tenantA, "First"}, {tenantB, "Second"}} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
			TenantID: tenant.id, Data: tenantRegistered(tenant.name)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantA, SchemaVersion: 999, Data: ownerCreated(uuid.NewString(), "First owner")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantB, Data: ownerCreated(uuid.NewString(), "Second owner")}); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st)
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up stopped before an independent tenant: %v", err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("first tenant remains available: %v", err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Fatalf("second tenant owner count after catch-up = %d, want 1", count)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild stopped before an independent tenant: %v", err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("first tenant remains available after rebuild: %v", err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Fatalf("second tenant owner count after rebuild = %d, want 1", count)
	}
}

func TestUnsupportedTenantLifecycleSchemaStopsReplay(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
		TenantID: tenantA, SchemaVersion: 999, Data: tenantRegistered("First")}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("tenant lifecycle replay = %v, want schema refusal", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || quarantined {
		t.Fatalf("tenant lifecycle quarantine = %t, err = %v", quarantined, err)
	}
}
