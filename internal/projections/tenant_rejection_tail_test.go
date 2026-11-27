// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestTailWorkerConfinesRejectedTenantEvent(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantA, Data: ownerCreated("not-a-uuid", "unprojectable")}); err != nil {
		t.Fatal(err)
	}
	healthy, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantB, Data: ownerCreated("00000000-0000-4000-8000-0000000000a1", "projectable")})
	if err != nil {
		t.Fatal(err)
	}
	worker := projections.NewTailWorker(log, projections.New(st), nil, time.Second)
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if count := ownerCount(t, st, tenantB); count == 1 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("tail stopped before later tenant projected: %v", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Fatalf("later tenant owner count=%d, want 1", count)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("rejected tenant quarantine=%t, err=%v", quarantined, err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantB); err != nil || quarantined {
		t.Fatalf("healthy tenant quarantine=%t, err=%v", quarantined, err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("rejected tenant service=%v, want suspended", err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantB); err != nil {
		t.Fatalf("healthy tenant service=%v", err)
	}
	if health, err := st.ProjectionTailHealth(ctx); err != nil || health.AppliedSequence != healthy.Sequence || health.FailedSequence != 0 {
		t.Fatalf("tail health=%+v, err=%v", health, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tail did not stop")
	}
}

func TestStartupReplayConfinesRejectedTenantEvent(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
			TenantID: tenant, Data: tenantRegistered(tenant)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantA, Data: ownerCreated("not-a-uuid", "unprojectable")}); err != nil {
		t.Fatal(err)
	}
	last, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantB, Data: ownerCreated("00000000-0000-4000-8000-0000000000b1", "projectable")})
	if err != nil {
		t.Fatal(err)
	}
	proj := projections.New(st)
	if err := proj.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("startup catch-up: %v", err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Fatalf("healthy owner count after catch-up=%d, want 1", count)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("catch-up quarantine=%t, err=%v", quarantined, err)
	}
	if checkpoint, err := st.ProjectionCheckpoint(ctx); err != nil || checkpoint != last.Sequence {
		t.Fatalf("catch-up checkpoint=%d, err=%v", checkpoint, err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := proj.Rebuild(ctx, log); err != nil {
		t.Fatalf("full rebuild: %v", err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Fatalf("healthy owner count after rebuild=%d, want 1", count)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("rebuild quarantine=%t, err=%v", quarantined, err)
	}
}
