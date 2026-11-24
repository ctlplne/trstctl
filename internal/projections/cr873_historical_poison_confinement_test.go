// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// A pre-upgrade NUL event can already be in the immutable stream. Raw JetStream
// publication models that retained history without weakening the new append guard.
// The poisoned tenant must be unavailable while later tenants still catch up.
func TestCR873HistoricalPoisonConfinesTenantDuringCatchUp(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "cr873-historical-poison", JetStream: true, StoreDir: t.TempDir(), Port: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		t.Fatal("external file-backed NATS did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSExternal, URL: srv.ClientURL(), Replicas: 1, AllowSingleReplica: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, tenant := range []struct{ id, name string }{{tenantA, "Poisoned"}, {tenantB, "Healthy"}} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant.id, Data: tenantRegistered(tenant.name)}); err != nil {
			t.Fatal(err)
		}
	}

	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	poisonPayload, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: "poisoned-member", DisplayName: "bad\x00name", Email: "member@example.test", Roles: []string{}, Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(map[string]any{
		"id": uuid.NewString(), "type": projections.EventTenantMemberUpserted,
		"tenant_id": tenantA, "time": time.Now().UTC(), "data": poisonPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	poison, err := js.Publish(ctx, "events."+projections.EventTenantMemberUpserted, stored)
	if err != nil {
		t.Fatal(err)
	}
	later, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB,
		Data: ownerCreated(uuid.NewString(), "unrelated later owner")})
	if err != nil {
		t.Fatal(err)
	}
	if later.Sequence <= poison.Sequence {
		t.Fatalf("later seq %d must follow poison seq %d", later.Sequence, poison.Sequence)
	}

	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("one tenant's old NUL event blocked all-tenants catch-up: %v", err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Errorf("healthy tenant owner count = %d, want 1", count)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Errorf("poisoned tenant admission = %v, want refusal", err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantB); err != nil {
		t.Errorf("healthy tenant admission = %v", err)
	}
	checkpoint, err := st.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint < later.Sequence {
		t.Errorf("checkpoint = %d, want >= later seq %d", checkpoint, later.Sequence)
	}
	if _, err := st.GetTenant(ctx, tenantA); err != nil {
		t.Fatalf("poisoned tenant registration missing before offboard: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("durable quarantine missing before offboard: quarantined=%v err=%v", quarantined, err)
	}
	// A restored database can lack the quarantine row while retaining the old
	// JetStream event. Rebuild must rediscover it before tenant offboarding.
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild without preexisting quarantine: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Errorf("rebuild did not rediscover quarantine: quarantined=%v err=%v", quarantined, err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Errorf("healthy owner after fresh quarantine discovery = %d, want 1", count)
	}
	// Quarantine cannot suppress a later key-custody event. The tenant still
	// needs to erase its state while other tenants continue to project.
	offboard, err := json.Marshal(map[string]int{"rows_deleted": 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantOffboarded, TenantID: tenantA, Data: offboard}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up after quarantined tenant offboard: %v", err)
	}
	if _, err := st.GetTenant(ctx, tenantA); !store.IsNotFound(err) {
		t.Errorf("quarantined tenant offboard did not erase registration: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || quarantined {
		t.Errorf("offboard retained prior lifecycle quarantine: quarantined=%v err=%v", quarantined, err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Errorf("healthy tenant owner count after offboard = %d, want 1", count)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("atomic rebuild of quarantined history blocked healthy tenant: %v", err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Errorf("healthy tenant owner count after rebuild = %d, want 1", count)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Errorf("poisoned tenant admission after rebuild = %v, want refusal", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || quarantined {
		t.Errorf("atomic rebuild retained offboarded lifecycle quarantine: quarantined=%v err=%v", quarantined, err)
	}
	// A later registration with the same UUID is a new lifecycle. The old
	// poison was quarantined and then erased by the retained offboard event.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("New lifecycle")}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("new lifecycle catch-up after old poison: %v", err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); err != nil {
		t.Errorf("new lifecycle refused after old poison: %v", err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("new lifecycle atomic rebuild after old poison: %v", err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); err != nil {
		t.Errorf("new lifecycle refused after atomic rebuild: %v", err)
	}
	// Project is the from-scratch replay entry point; use an empty read model
	// after checking the in-place atomic rebuild above.
	fresh := newStore(t)
	if err := projections.New(fresh).Project(ctx, log); err != nil {
		t.Fatalf("explicit full replay blocked healthy tenant on old poison: %v", err)
	}
	if err := fresh.RequireLiveTenantService(ctx, tenantA); err != nil {
		t.Errorf("new lifecycle refused after full replay: %v", err)
	}
	if count := ownerCount(t, fresh, tenantB); count != 1 {
		t.Errorf("healthy owner after full replay = %d, want 1", count)
	}
}

func TestCR873HistoricalPoisonConfinesTenantDuringLiveTail(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "cr873-historical-tail", JetStream: true, StoreDir: t.TempDir(), Port: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		t.Fatal("external file-backed NATS did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSExternal, URL: srv.ClientURL(), Replicas: 1, AllowSingleReplica: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, tenant := range []struct{ id, name string }{{tenantA, "Poisoned"}, {tenantB, "Healthy"}} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant.id, Data: tenantRegistered(tenant.name)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("clean registration catch-up: %v", err)
	}
	tailCtx, cancel := context.WithCancel(ctx)
	tailDone := make(chan error, 1)
	go func() { tailDone <- projections.NewTailWorker(log, projections.New(st), nil, time.Second).Run(tailCtx) }()
	defer func() {
		cancel()
		select {
		case err := <-tailDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("tail stopped with error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("tail did not stop after cancellation")
		}
	}()
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	poisonPayload, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: "poisoned-member", DisplayName: "bad\x00name", Email: "member@example.test", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(map[string]any{
		"id": uuid.NewString(), "type": projections.EventTenantMemberUpserted,
		"tenant_id": tenantA, "time": time.Now().UTC(), "data": poisonPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, "events."+projections.EventTenantMemberUpserted, stored); err != nil {
		t.Fatal(err)
	}
	later, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB,
		Data: ownerCreated(uuid.NewString(), "later healthy owner")})
	if err != nil {
		t.Fatal(err)
	}
	projected := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if ownerCount(t, st, tenantB) == 1 {
			projected = true
			break
		}
	}
	if !projected {
		t.Errorf("healthy tenant owner event %d did not project after old poison", later.Sequence)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Errorf("poisoned tenant admission = %v, want refusal", err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantB); err != nil {
		t.Errorf("healthy tenant admission = %v", err)
	}
	health, err := st.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.FailedSequence != 0 || health.AppliedSequence < later.Sequence {
		t.Errorf("global tail health = %+v, want clean through %d", health, later.Sequence)
	}
}
