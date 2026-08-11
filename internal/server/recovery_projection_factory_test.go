// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type recoveryReceiptProjection struct {
	resets  int
	applied []events.Event
}

func (p *recoveryReceiptProjection) Name() string { return "test.recovery.receipt" }

func (p *recoveryReceiptProjection) Reset(context.Context) error {
	p.resets++
	p.applied = nil
	return nil
}

func (p *recoveryReceiptProjection) Apply(_ context.Context, event events.Event) error {
	p.applied = append(p.applied, event)
	return nil
}

func TestRecoveryProjectionFactoryJoinsTheActualRebuild(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, events.Event{
		ID: "licensed-recovery-receipt", Type: "licensed.recovery.receipt", TenantID: store.ZeroUUID,
	}); err != nil {
		t.Fatalf("append extension event: %v", err)
	}

	receipt := &recoveryReceiptProjection{}
	called := 0
	factory := func(
		_ context.Context,
		_ *config.Config,
		lic *license.Manager,
		gotStore *store.Store,
		gotLog *events.Log,
	) ([]projections.Option, error) {
		called++
		if lic == nil || lic.Tier() != license.TierCommunity {
			t.Fatalf("recovery factory license = %#v, want loaded Community manager", lic)
		}
		if gotStore != st || gotLog != log {
			t.Fatal("recovery factory did not receive the exact recovered stores")
		}
		return []projections.Option{projections.WithEventProjection(receipt)}, nil
	}
	options, err := recoveryProjectionOptions(ctx, config.Default(), st, log,
		[]EditionProjectionOptionsFactory{factory})
	if err != nil {
		t.Fatalf("recoveryProjectionOptions: %v", err)
	}
	if err := projections.New(st, options...).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild with licensed extension: %v", err)
	}
	if called != 1 || receipt.resets != 1 || len(receipt.applied) != 1 ||
		receipt.applied[0].ID != "licensed-recovery-receipt" {
		t.Fatalf("factory/rebuild receipt = called %d, resets %d, events %+v", called, receipt.resets, receipt.applied)
	}
}

type lifecycleAssemblyRegressionProjection struct {
	store           *store.Store
	resets          int
	transactional   int
	postCommitCalls int
	replayed        []string
	replayLive      map[string]bool
	ordinaryIDs     []string
	duringReplay    func(events.Event) error
}

func (p *lifecycleAssemblyRegressionProjection) Name() string {
	return "test.tenant_lifecycle_assembly"
}

func (p *lifecycleAssemblyRegressionProjection) ProjectsTenantLifecycle() {}

func (p *lifecycleAssemblyRegressionProjection) Reset(context.Context) error {
	p.resets++
	p.replayed = nil
	p.replayLive = make(map[string]bool)
	p.ordinaryIDs = nil
	return nil
}

func (p *lifecycleAssemblyRegressionProjection) ResetTx(context.Context, pgx.Tx) error {
	p.resets++
	p.replayed = nil
	p.replayLive = make(map[string]bool)
	p.ordinaryIDs = nil
	return nil
}

func (p *lifecycleAssemblyRegressionProjection) ReplayTenantLifecycleTx(
	_ context.Context,
	_ pgx.Tx,
	event events.Event,
) error {
	// Boot replay is deliberately independent of the current core tenants row:
	// that row may still be at an older checkpoint, or already represent the
	// final state after several retained lifecycle transitions.
	p.replayed = append(p.replayed, event.Type)
	switch event.Type {
	case projections.EventTenantRegistered:
		p.replayLive[event.TenantID] = true
	case projections.EventTenantOffboarded:
		p.replayLive[event.TenantID] = false
	}
	if p.duringReplay != nil {
		return p.duringReplay(event)
	}
	return nil
}

func (p *lifecycleAssemblyRegressionProjection) Apply(
	ctx context.Context,
	event events.Event,
) error {
	if event.Type != projections.EventTenantRegistered &&
		event.Type != projections.EventTenantOffboarded {
		p.ordinaryIDs = append(p.ordinaryIDs, event.ID)
		return nil
	}
	p.postCommitCalls++
	// This is deliberately destructive regression behavior. If the live command
	// ever dispatches tenant.registered through Apply after releasing lifecycle,
	// the extension can late-delete the newly registered tenant.
	_, err := p.store.SystemPool().Exec(ctx,
		`DELETE FROM tenants WHERE tenant_id = $1`, event.TenantID)
	return err
}

func (p *lifecycleAssemblyRegressionProjection) ApplyTx(
	ctx context.Context,
	tx pgx.Tx,
	event events.Event,
) error {
	if event.Type != projections.EventTenantRegistered {
		return nil
	}
	var sequence int64
	if err := tx.QueryRow(ctx,
		`SELECT event_seq FROM tenants WHERE tenant_id = $1`, event.TenantID).Scan(&sequence); err != nil {
		return fmt.Errorf("test lifecycle extension cannot see core registration: %w", err)
	}
	if sequence != int64(event.Sequence) { // #nosec G115 -- event test sequence is PostgreSQL bigint-bounded.
		return fmt.Errorf("test lifecycle extension saw sequence %d, want %d", sequence, event.Sequence)
	}
	p.transactional++
	return nil
}

func TestBuildSharesConfiguredProjectorWithLiveTenantLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true,
	})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	receipt := &lifecycleAssemblyRegressionProjection{store: st}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log,
		LicensedProjectionOptions: []projections.Option{
			projections.WithEventProjection(receipt),
		},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	const tenantID = "a1090000-0000-4000-8000-000000000001"
	created, err := srv.orch.ProvisionManagedTenant(
		ctx,
		"a1090000-0000-4000-8000-000000000002",
		"aud109-live-lifecycle",
		orchestrator.ManagedTenantProvisionRequest{TenantID: tenantID, Name: "AUD-109"},
	)
	if err != nil {
		t.Fatalf("ProvisionManagedTenant: %v", err)
	}
	if receipt.resets != 1 || receipt.transactional != 1 || receipt.postCommitCalls != 0 {
		t.Fatalf(
			"configured projection resets=%d transactional=%d post_commit=%d, want 1/1/0",
			receipt.resets, receipt.transactional, receipt.postCommitCalls,
		)
	}
	projected, err := st.GetTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("load tenant after lifecycle extension: %v", err)
	}
	if projected.EventSeq != created.EventSequence {
		t.Fatalf("projected tenant sequence=%d, want %d", projected.EventSeq, created.EventSequence)
	}
	canonical, found, err := log.EventAtSequence(ctx, created.EventSequence)
	if err != nil || !found {
		t.Fatalf("load canonical registration found=%v err=%v", found, err)
	}
	err = projections.New(st, projections.WithEventProjection(receipt)).Apply(ctx, canonical)
	if err == nil || !strings.Contains(err.Error(), "transactional tenant lifecycle dispatch") {
		t.Fatalf("ordinary Apply lifecycle error=%v, want loud transactional-dispatch refusal", err)
	}
	if receipt.postCommitCalls != 0 {
		t.Fatalf("ordinary Apply invoked destructive post-commit projection %d time(s)", receipt.postCommitCalls)
	}
}

func TestProjectCatchUpSeparatesLifecycleExtensionReplayFromLiveCoreState(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true,
	})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	const tenantID = "a1090000-0000-4000-8000-000000000021"
	firstData, _ := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: "first registration"})
	first, err := log.Append(ctx, events.Event{
		ID:   "tenant-registration-a1090000-0000-4000-8000-000000000022",
		Type: projections.EventTenantRegistered, TenantID: tenantID,
		SchemaVersion: events.DefaultSchemaVersion, Data: firstData,
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("append first registration: %v", err)
	}
	offboardData, _ := json.Marshal(struct {
		RowsDeleted int `json:"rows_deleted"`
	}{RowsDeleted: 4})
	if _, err := log.Append(ctx, events.Event{
		ID:   projections.TenantOffboardEventID(tenantID, first.ID),
		Type: projections.EventTenantOffboarded, TenantID: tenantID,
		SchemaVersion: events.DefaultSchemaVersion, Data: offboardData,
	}); err != nil {
		_ = log.Close()
		t.Fatalf("append offboard: %v", err)
	}
	secondData, _ := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: "second registration"})
	second, err := log.Append(ctx, events.Event{
		ID:   "tenant-registration-a1090000-0000-4000-8000-000000000023",
		Type: projections.EventTenantRegistered, TenantID: tenantID,
		SchemaVersion: events.DefaultSchemaVersion, Data: secondData,
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("append second registration: %v", err)
	}

	receipt := &lifecycleAssemblyRegressionProjection{store: st}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log,
		LicensedProjectionOptions: []projections.Option{
			projections.WithEventProjection(receipt),
		},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build with retained lifecycle history: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	wantReplay := []string{
		projections.EventTenantRegistered,
		projections.EventTenantOffboarded,
		projections.EventTenantRegistered,
	}
	if !reflect.DeepEqual(receipt.replayed, wantReplay) || !receipt.replayLive[tenantID] {
		t.Fatalf("startup lifecycle replay=(%v, live:%t), want (%v, true)",
			receipt.replayed, receipt.replayLive[tenantID], wantReplay)
	}
	if receipt.transactional != 0 || receipt.postCommitCalls != 0 {
		t.Fatalf("startup invoked live/post-commit lifecycle paths=%d/%d, want 0/0",
			receipt.transactional, receipt.postCommitCalls)
	}
	projected, err := st.GetTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("load final caught-up tenant: %v", err)
	}
	if projected.Name != "second registration" || projected.EventSeq != second.Sequence {
		t.Fatalf("caught-up tenant=(%q,%d), want (%q,%d)",
			projected.Name, projected.EventSeq, "second registration", second.Sequence)
	}
}

func TestProjectCatchUpPinsOneHeadAcrossExtensionAndCoreThenRestartCatchesTail(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true,
	})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	const tenantID = "a1090000-0000-4000-8000-000000000031"
	firstData, _ := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: "first registration"})
	first, err := log.Append(ctx, events.Event{
		ID:   "tenant-registration-a1090000-0000-4000-8000-000000000032",
		Type: projections.EventTenantRegistered, TenantID: tenantID,
		SchemaVersion: events.DefaultSchemaVersion, Data: firstData,
	})
	if err != nil {
		t.Fatalf("append first registration: %v", err)
	}

	var appended bool
	var ordinary, second events.Event
	firstPass := &lifecycleAssemblyRegressionProjection{store: st}
	firstPass.duringReplay = func(event events.Event) error {
		if appended || event.ID != first.ID {
			return nil
		}
		appended = true
		offboardData, _ := json.Marshal(struct {
			RowsDeleted int `json:"rows_deleted"`
		}{RowsDeleted: 3})
		if _, err := log.Append(ctx, events.Event{
			ID:   projections.TenantOffboardEventID(tenantID, first.ID),
			Type: projections.EventTenantOffboarded, TenantID: tenantID,
			SchemaVersion: events.DefaultSchemaVersion, Data: offboardData,
		}); err != nil {
			return err
		}
		ordinary, err = log.Append(ctx, events.Event{
			ID: "aud109-extension-between-passes", Type: "test.extension.ordinary",
			TenantID: tenantID, SchemaVersion: events.DefaultSchemaVersion,
			Data: []byte(`{"value":"after-head"}`),
		})
		if err != nil {
			return err
		}
		secondData, _ := json.Marshal(struct {
			Name string `json:"name"`
		}{Name: "second registration"})
		second, err = log.Append(ctx, events.Event{
			ID:   "tenant-registration-a1090000-0000-4000-8000-000000000033",
			Type: projections.EventTenantRegistered, TenantID: tenantID,
			SchemaVersion: events.DefaultSchemaVersion, Data: secondData,
		})
		return err
	}
	if err := projections.New(st, projections.WithEventProjection(firstPass)).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("first pinned catch-up: %v", err)
	}
	checkpoint, err := st.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatalf("read first checkpoint: %v", err)
	}
	if checkpoint != first.Sequence {
		t.Fatalf("first checkpoint=%d, want pinned head %d", checkpoint, first.Sequence)
	}
	if !reflect.DeepEqual(firstPass.replayed, []string{projections.EventTenantRegistered}) ||
		len(firstPass.ordinaryIDs) != 0 {
		t.Fatalf("first extension replay lifecycle=%v ordinary=%v, want only initial registration",
			firstPass.replayed, firstPass.ordinaryIDs)
	}
	projected, err := st.GetTenant(ctx, tenantID)
	if err != nil || projected.EventSeq != first.Sequence {
		t.Fatalf("tenant after pinned pass=%+v err=%v, want first registration", projected, err)
	}

	// A restarted projector begins at the saved head. Its full extension replay
	// and bounded core tail both include the events appended by the first pass.
	secondPass := &lifecycleAssemblyRegressionProjection{store: st}
	if err := projections.New(st, projections.WithEventProjection(secondPass)).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("restart catch-up: %v", err)
	}
	wantLifecycle := []string{
		projections.EventTenantRegistered,
		projections.EventTenantOffboarded,
		projections.EventTenantRegistered,
	}
	if !reflect.DeepEqual(secondPass.replayed, wantLifecycle) ||
		!reflect.DeepEqual(secondPass.ordinaryIDs, []string{ordinary.ID}) ||
		!secondPass.replayLive[tenantID] {
		t.Fatalf("restart extension replay lifecycle=%v ordinary=%v live=%t",
			secondPass.replayed, secondPass.ordinaryIDs, secondPass.replayLive[tenantID])
	}
	checkpoint, err = st.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatalf("read restart checkpoint: %v", err)
	}
	if checkpoint != second.Sequence {
		t.Fatalf("restart checkpoint=%d, want tail head %d", checkpoint, second.Sequence)
	}
	projected, err = st.GetTenant(ctx, tenantID)
	if err != nil || projected.Name != "second registration" || projected.EventSeq != second.Sequence {
		t.Fatalf("tenant after restart=%+v err=%v, want second registration seq %d",
			projected, err, second.Sequence)
	}
}
