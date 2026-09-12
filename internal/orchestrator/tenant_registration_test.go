// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestTenantRegistrationDifferentKeyPreclaimRacePublishesOnce(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	ctx := events.ContextWithActor(context.Background(), events.Actor{
		Subject: "tenant-bootstrapper", Roles: []string{"writer", "admin", "writer"},
	})

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, key := range []string{"registration-a", "registration-b"} {
		key := key
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := orchestrator.ExecuteTenantRegistration(
				ctx, log, st, projector, orchestrator.NewIdempotency(st),
				registrationCommand(tenantA, "tenant-a", key),
			)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
			continue
		}
		if !errors.Is(err, orchestrator.ErrInProgress) &&
			!errors.Is(err, store.ErrTenantRegistrationConflict) {
			t.Fatalf("losing registration error = %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful registrations = %d, want exactly 1", succeeded)
	}
	if got := countTenantEvents(t, log, tenantA, projections.EventTenantRegistered); got != 1 {
		t.Fatalf("tenant.registered events = %d, want exactly 1", got)
	}
	var rows, pending int
	if err := st.SystemPool().QueryRow(context.Background(), `
		SELECT count(*), count(*) FILTER (WHERE status = 'pending')
		  FROM idempotency_keys
		 WHERE tenant_id = $1`, tenantA).Scan(&rows, &pending); err != nil {
		t.Fatalf("count registration receivers: %v", err)
	}
	if rows != 1 || pending != 0 {
		t.Fatalf("registration receivers rows=%d pending=%d, want one completed winner", rows, pending)
	}
}

func TestTenantRegistrationSameRawKeyAfterOffboardGetsNewIdentity(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	ctx := context.Background()
	command := registrationCommand(tenantA, "tenant-a", "same-key")

	first, err := orchestrator.ExecuteTenantRegistration(
		ctx, log, st, projector, orchestrator.NewIdempotency(st), command)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if _, err := st.OffboardTenant(ctx, tenantA); err != nil {
		t.Fatalf("offboard tenant: %v", err)
	}
	second, err := orchestrator.ExecuteTenantRegistration(
		ctx, log, st, projector, orchestrator.NewIdempotency(st), command)
	if err != nil {
		t.Fatalf("second registration: %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("re-registration reused event id %q", first.ID)
	}
	if first.Time.Equal(second.Time) {
		t.Fatalf("re-registration reused event time %s", first.Time)
	}
}

func TestTenantRegistrationAppendSuccessResultFailureReplaysWithoutSecondEvent(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	command := registrationCommand(tenantA, "tenant-a", "result-recovery")
	if _, err := orchestrator.ExecuteTenantRegistration(
		context.Background(), log, st, projector,
		orchestrator.NewIdempotency(st, orchestrator.WithResultProtector(failingRegistrationProtector{})),
		command,
	); err == nil {
		t.Fatal("first registration should surface result protection failure")
	}
	projected, err := st.GetTenant(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("load projection after result failure: %v", err)
	}
	first, found, err := log.EventAtSequence(context.Background(), projected.EventSeq)
	if err != nil || !found {
		t.Fatalf("load retained registration found=%v err=%v", found, err)
	}
	replayed, err := orchestrator.ExecuteTenantRegistration(
		context.Background(), log, st, projector, orchestrator.NewIdempotency(st), command)
	if err != nil {
		t.Fatalf("recover registration result: %v", err)
	}
	if replayed.ID != first.ID || replayed.Sequence != first.Sequence {
		t.Fatalf("recovered identity = (%q,%d), want (%q,%d)",
			replayed.ID, replayed.Sequence, first.ID, first.Sequence)
	}
	if got := countTenantEvents(t, log, tenantA, projections.EventTenantRegistered); got != 1 {
		t.Fatalf("tenant.registered events = %d after result recovery, want 1", got)
	}
}

func TestTenantRegistrationLateOldCompletionCannotMatchNewLifecycle(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	protector := &blockingRegistrationProtector{
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	command := registrationCommand(tenantA, "tenant-a", "same-key")
	firstDone := make(chan error, 1)
	go func() {
		_, err := orchestrator.ExecuteTenantRegistration(
			context.Background(), log, st, projector,
			orchestrator.NewIdempotency(st, orchestrator.WithResultProtector(protector)),
			command,
		)
		firstDone <- err
	}()

	select {
	case <-protector.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("first registration did not reach result protection")
	}
	if _, err := st.OffboardTenant(context.Background(), tenantA); err != nil {
		close(protector.release)
		t.Fatalf("offboard tenant: %v", err)
	}
	second, err := orchestrator.ExecuteTenantRegistration(
		context.Background(), log, st, projector, orchestrator.NewIdempotency(st), command)
	if err != nil {
		close(protector.release)
		t.Fatalf("new lifecycle registration: %v", err)
	}
	close(protector.release)
	if err := <-firstDone; !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("late old completion error = %v, want ErrIdempotencyConflict", err)
	}
	projected, err := st.GetTenant(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("load new lifecycle: %v", err)
	}
	if projected.EventSeq != second.Sequence {
		t.Fatalf("live event sequence = %d, want new lifecycle %d", projected.EventSeq, second.Sequence)
	}
}

func TestTenantRegistrationActorRolesCanonicalizeBeforeBinding(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	command := registrationCommand(tenantA, "tenant-a", "canonical-roles")
	firstCtx := events.ContextWithActor(context.Background(), events.Actor{
		Subject: "bootstrapper", Roles: []string{"writer", "admin", "writer"},
	})
	first, err := orchestrator.ExecuteTenantRegistration(
		firstCtx, log, st, projector, orchestrator.NewIdempotency(st), command)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	replayCtx := events.ContextWithActor(context.Background(), events.Actor{
		Subject: "bootstrapper", Roles: []string{"admin", "writer"},
	})
	replayed, err := orchestrator.ExecuteTenantRegistration(
		replayCtx, log, st, projector, orchestrator.NewIdempotency(st), command)
	if err != nil {
		t.Fatalf("canonical role replay: %v", err)
	}
	if replayed.ID != first.ID || replayed.Sequence != first.Sequence {
		t.Fatalf("replay identity = (%q,%d), want (%q,%d)",
			replayed.ID, replayed.Sequence, first.ID, first.Sequence)
	}
	if first.Actor == nil || len(first.Actor.Roles) != 2 ||
		first.Actor.Roles[0] != "admin" || first.Actor.Roles[1] != "writer" {
		t.Fatalf("canonical actor roles = %#v", first.Actor)
	}
}

func TestLiveTenantRegistrationAuthorityBindsExactRetainedEnvelope(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	registered, err := orchestrator.ExecuteTenantRegistration(
		context.Background(), log, st, projections.New(st),
		orchestrator.NewIdempotency(st),
		registrationCommand(tenantA, "tenant-a", "registration-authority"),
	)
	if err != nil {
		t.Fatalf("register tenant: %v", err)
	}
	authority, err := orchestrator.ResolveLiveTenantRegistrationAuthority(
		context.Background(), log, st, tenantA,
	)
	if err != nil {
		t.Fatalf("resolve registration authority: %v", err)
	}
	if authority.EventID != registered.ID || authority.EventSequence != registered.Sequence {
		t.Fatalf("registration authority=(%q,%d), want (%q,%d)",
			authority.EventID, authority.EventSequence, registered.ID, registered.Sequence)
	}

	if _, err := st.SystemPool().Exec(context.Background(), `
		UPDATE tenants SET event_seq = $2 WHERE tenant_id = $1`,
		tenantA, int64(registered.Sequence+100)); err != nil { // #nosec G115 -- bounded test sequence.
		t.Fatalf("corrupt tenant registration sequence: %v", err)
	}
	if _, err := orchestrator.ResolveLiveTenantRegistrationAuthority(
		context.Background(), log, st, tenantA,
	); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("corrupt registration authority error=%v, want ErrIdempotencyConflict", err)
	}
}

func TestLiveTenantRegistrationAuthorityAcceptsUpgradedLegacyEventIdentity(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	const legacyEventID = "77777777-7777-4777-8777-777777777777"
	registered, err := log.Append(ctx, events.Event{
		ID: legacyEventID, Type: projections.EventTenantRegistered,
		TenantID: tenantA, Data: tenantRegisteredJSON("legacy-live-tenant"),
	})
	if err != nil {
		t.Fatalf("append legacy registration: %v", err)
	}
	if err := projections.New(st).ApplyRetainedTenantLifecycle(ctx, registered); err != nil {
		t.Fatalf("project legacy registration: %v", err)
	}

	authority, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantA)
	if err != nil {
		t.Fatalf("resolve upgraded legacy authority: %v", err)
	}
	if authority.EventID != legacyEventID || authority.EventSequence != registered.Sequence {
		t.Fatalf("legacy authority=(%q,%d), want (%q,%d)",
			authority.EventID, authority.EventSequence, legacyEventID, registered.Sequence)
	}
}

type tenantLifecycleRegressionProjection struct {
	store           *store.Store
	registeredTx    int
	offboardedTx    int
	postCommitCalls int
}

func (p *tenantLifecycleRegressionProjection) Name() string {
	return "test.tenant_lifecycle_fence"
}

func (*tenantLifecycleRegressionProjection) ProjectsTenantLifecycle() {}

func (*tenantLifecycleRegressionProjection) Reset(context.Context) error { return nil }

func (*tenantLifecycleRegressionProjection) ResetTx(context.Context, pgx.Tx) error { return nil }

func (*tenantLifecycleRegressionProjection) ReplayTenantLifecycleTx(
	context.Context,
	pgx.Tx,
	events.Event,
) error {
	return nil
}

func (p *tenantLifecycleRegressionProjection) Apply(
	ctx context.Context,
	event events.Event,
) error {
	switch event.Type {
	case projections.EventTenantRegistered:
		p.postCommitCalls++
		// If live registration ever dispatches here after lifecycle unlock, this
		// deliberately models a stale extension that late-deletes the new row.
		_, err := p.store.SystemPool().Exec(ctx,
			`DELETE FROM tenants WHERE tenant_id = $1`, event.TenantID)
		return err
	case projections.EventTenantOffboarded:
		p.postCommitCalls++
		// The inverse stale extension would resurrect an erased UUID.
		_, err := p.store.SystemPool().Exec(ctx, `
			INSERT INTO tenants (tenant_id, name, event_seq)
			VALUES ($1, 'stale-extension-resurrection', $2)
			ON CONFLICT (tenant_id) DO UPDATE
			SET name = EXCLUDED.name, event_seq = EXCLUDED.event_seq`,
			event.TenantID, int64(event.Sequence)) // #nosec G115 -- test event sequence is PostgreSQL bigint-bounded.
		return err
	default:
		return nil
	}
}

func (p *tenantLifecycleRegressionProjection) ApplyTx(
	ctx context.Context,
	tx pgx.Tx,
	event events.Event,
) error {
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM tenants WHERE tenant_id = $1)`,
		event.TenantID).Scan(&exists); err != nil {
		return err
	}
	switch event.Type {
	case projections.EventTenantRegistered:
		if !exists {
			return errors.New("test lifecycle extension cannot see core registration")
		}
		p.registeredTx++
	case projections.EventTenantOffboarded:
		if exists {
			return errors.New("test lifecycle extension can still see core tenant after offboard")
		}
		p.offboardedTx++
	}
	return nil
}

func TestTenantOffboardErasedReceiverRecoveryAndLifecycleProjectionFence(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	extension := &tenantLifecycleRegressionProjection{store: st}
	projector := projections.New(st, projections.WithEventProjection(extension))
	command := registrationCommand(tenantA, "tenant-a", "offboard-recovery")
	if _, err := orchestrator.ExecuteTenantRegistration(
		context.Background(), log, st, projector, orchestrator.NewIdempotency(st), command,
	); err != nil {
		t.Fatalf("register tenant: %v", err)
	}

	offboardPayload, _ := json.Marshal(struct {
		RowsDeleted int `json:"rows_deleted"`
	}{RowsDeleted: 9})
	next := events.Event{
		Type: projections.EventTenantOffboarded, TenantID: tenantA,
		SchemaVersion: events.DefaultSchemaVersion, Data: offboardPayload,
	}
	orch := orchestrator.NewOrchestrator(
		log, st, nil, orchestrator.WithProjector(projector),
	)
	first, err := orchestrator.EmitTenantOffboardForTest(context.Background(), orch, next)
	if err != nil {
		t.Fatalf("first offboard: %v", err)
	}
	if _, err := st.GetTenant(context.Background(), tenantA); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant after offboard error=%v, want pgx.ErrNoRows", err)
	}

	// Offboard committed by deleting both SQL anchors. The exact retry pays for
	// one pinned lifecycle fold and returns the retained event, not a new append.
	retryPayload, _ := json.Marshal(struct {
		RowsDeleted int `json:"rows_deleted"`
	}{})
	retry := next
	retry.Data = retryPayload
	replayed, err := orchestrator.EmitTenantOffboardForTest(context.Background(), orch, retry)
	if err != nil {
		t.Fatalf("retry after receiver erase: %v", err)
	}
	if replayed.ID != first.ID || replayed.Sequence != first.Sequence ||
		!replayed.Time.Equal(first.Time) {
		t.Fatalf("recovered offboard=%+v, want retained %+v", replayed, first)
	}
	if got := countTenantEvents(t, log, tenantA, projections.EventTenantOffboarded); got != 1 {
		t.Fatalf("tenant.offboarded events=%d, want 1", got)
	}
	if extension.registeredTx != 1 || extension.offboardedTx != 2 ||
		extension.postCommitCalls != 0 {
		t.Fatalf(
			"extension registered_tx=%d offboarded_tx=%d post_commit=%d, want 1/2/0",
			extension.registeredTx, extension.offboardedTx, extension.postCommitCalls,
		)
	}

	second, err := orchestrator.ExecuteTenantRegistration(
		context.Background(), log, st, projector, orchestrator.NewIdempotency(st), command,
	)
	if err != nil {
		t.Fatalf("re-register tenant: %v", err)
	}
	oldRetry := next
	oldRetry.ID = first.ID
	if _, err := orchestrator.EmitTenantOffboardForTest(
		context.Background(), orch, oldRetry,
	); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("old-lifecycle offboard retry error=%v, want ErrIdempotencyConflict", err)
	}
	projected, err := st.GetTenant(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("load re-registered tenant: %v", err)
	}
	if projected.EventSeq != second.Sequence {
		t.Fatalf("old retry changed lifecycle sequence=%d, want %d", projected.EventSeq, second.Sequence)
	}
}

func TestTenantOffboardErasedReceiverRejectsCorruptLifecycleFold(t *testing.T) {
	tests := []struct {
		name   string
		append func(*testing.T, *events.Log)
	}{
		{
			name: "orphan offboard",
			append: func(t *testing.T, log *events.Log) {
				t.Helper()
				payload, _ := json.Marshal(struct {
					RowsDeleted int `json:"rows_deleted"`
				}{RowsDeleted: 1})
				if _, err := log.Append(context.Background(), events.Event{
					ID:   projections.TenantOffboardEventID(tenantA, "missing-registration"),
					Type: projections.EventTenantOffboarded, TenantID: tenantA,
					SchemaVersion: events.DefaultSchemaVersion, Data: payload,
				}); err != nil {
					t.Fatalf("append orphan offboard: %v", err)
				}
			},
		},
		{
			name: "consecutive registrations",
			append: func(t *testing.T, log *events.Log) {
				t.Helper()
				registrations := []struct {
					id   string
					name string
				}{
					{id: "tenant-registration-a1090000-0000-4000-8000-000000000011", name: "first"},
					{id: "tenant-registration-a1090000-0000-4000-8000-000000000012", name: "second"},
				}
				for _, registration := range registrations {
					payload, _ := json.Marshal(struct {
						Name string `json:"name"`
					}{Name: registration.name})
					if _, err := log.Append(context.Background(), events.Event{
						ID: registration.id, Type: projections.EventTenantRegistered,
						TenantID: tenantA, SchemaVersion: events.DefaultSchemaVersion,
						Data: payload,
					}); err != nil {
						t.Fatalf("append %s registration: %v", registration.name, err)
					}
				}
				offboardPayload, _ := json.Marshal(struct {
					RowsDeleted int `json:"rows_deleted"`
				}{RowsDeleted: 1})
				if _, err := log.Append(context.Background(), events.Event{
					ID:   projections.TenantOffboardEventID(tenantA, registrations[1].id),
					Type: projections.EventTenantOffboarded, TenantID: tenantA,
					SchemaVersion: events.DefaultSchemaVersion, Data: offboardPayload,
				}); err != nil {
					t.Fatalf("append offboard after consecutive registrations: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			log := openLog(t)
			tc.append(t, log)
			payload, _ := json.Marshal(struct {
				RowsDeleted int `json:"rows_deleted"`
			}{})
			orch := orchestrator.NewOrchestrator(
				log, st, nil, orchestrator.WithProjector(projections.New(st)),
			)
			_, err := orchestrator.EmitTenantOffboardForTest(
				context.Background(), orch, events.Event{
					Type: projections.EventTenantOffboarded, TenantID: tenantA,
					SchemaVersion: events.DefaultSchemaVersion, Data: payload,
				},
			)
			if !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
				t.Fatalf("corrupt erased lifecycle error=%v, want ErrIdempotencyConflict", err)
			}
		})
	}
}

func TestTenantOffboardErasedReceiverAcceptsLegacyRegistrationRename(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	registrations := []struct {
		id   string
		name string
	}{
		{id: "legacy-tenant-registration-original", name: "original name"},
		{id: "legacy-tenant-registration-rename", name: "renamed tenant"},
	}
	for _, registration := range registrations {
		payload, _ := json.Marshal(struct {
			Name string `json:"name"`
		}{Name: registration.name})
		if _, err := log.Append(context.Background(), events.Event{
			ID: registration.id, Type: projections.EventTenantRegistered,
			TenantID: tenantA, SchemaVersion: events.DefaultSchemaVersion,
			Data: payload,
		}); err != nil {
			t.Fatalf("append legacy registration %q: %v", registration.name, err)
		}
	}
	offboardPayload, _ := json.Marshal(struct {
		RowsDeleted int `json:"rows_deleted"`
	}{RowsDeleted: 6})
	offboard, err := log.Append(context.Background(), events.Event{
		ID:   projections.TenantOffboardEventID(tenantA, registrations[1].id),
		Type: projections.EventTenantOffboarded, TenantID: tenantA,
		SchemaVersion: events.DefaultSchemaVersion, Data: offboardPayload,
	})
	if err != nil {
		t.Fatalf("append legacy rename offboard: %v", err)
	}
	retryPayload, _ := json.Marshal(struct {
		RowsDeleted int `json:"rows_deleted"`
	}{})
	orch := orchestrator.NewOrchestrator(
		log, st, nil, orchestrator.WithProjector(projections.New(st)),
	)
	recovered, err := orchestrator.EmitTenantOffboardForTest(
		context.Background(), orch, events.Event{
			Type: projections.EventTenantOffboarded, TenantID: tenantA,
			SchemaVersion: events.DefaultSchemaVersion, Data: retryPayload,
		},
	)
	if err != nil {
		t.Fatalf("recover legacy rename offboard: %v", err)
	}
	if recovered.ID != offboard.ID || recovered.Sequence != offboard.Sequence {
		t.Fatalf("recovered legacy offboard=(%q,%d), want (%q,%d)",
			recovered.ID, recovered.Sequence, offboard.ID, offboard.Sequence)
	}
}

func registrationCommand(tenantID, name, key string) orchestrator.TenantRegistrationCommand {
	payload, _ := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: name})
	return orchestrator.TenantRegistrationCommand{
		TenantID: tenantID, Name: name, IdempotencyKey: key,
		RequestMaterial: append([]byte(nil), payload...),
		PayloadAt: func(time.Time) ([]byte, error) {
			return append([]byte(nil), payload...), nil
		},
	}
}

func TestInitialTenantRegistrationCannotResurrectErasedTenant(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	command := registrationCommand(tenantA, "evaluation", "eval-registration")
	command.InitialOnly = true
	execute := func() (events.Event, error) {
		return orchestrator.ExecuteTenantRegistration(t.Context(), log, st, projector, orchestrator.NewIdempotency(st), command)
	}
	first, err := execute()
	if err != nil {
		t.Fatal(err)
	}
	again, err := execute()
	if err != nil || first.ID != again.ID || first.Sequence != again.Sequence {
		t.Fatalf("initial registration retry changed its event: %+v %v", again, err)
	}
	if _, err := st.OffboardTenant(t.Context(), tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(); !errors.Is(err, store.ErrTenantRegistrationConflict) {
		t.Fatalf("automatic registration after erasure = %v", err)
	}
	if _, err := st.GetTenant(t.Context(), tenantA); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("erased tenant was recreated: %v", err)
	}
	if got := countTenantEvents(t, log, tenantA, projections.EventTenantRegistered); got != 1 {
		t.Fatalf("registration events = %d, want original only", got)
	}
	var receipts int
	if err := st.SystemPool().QueryRow(t.Context(), "SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1", tenantA).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("refusal retained a new registration intent: count=%d err=%v", receipts, err)
	}
}

func countTenantEvents(t *testing.T, log *events.Log, tenantID, eventType string) int {
	t.Helper()
	count := 0
	if err := log.Replay(context.Background(), 1, func(event events.Event) error {
		if event.TenantID == tenantID && event.Type == eventType {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay tenant events: %v", err)
	}
	return count
}

type blockingRegistrationProtector struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type failingRegistrationProtector struct{}

func (failingRegistrationProtector) Protect(
	context.Context,
	string, string, string,
	[]byte,
) (string, []byte, error) {
	return "", nil, errors.New("injected registration result protection failure")
}

func (failingRegistrationProtector) Open(
	context.Context,
	string, string, string, string,
	[]byte,
) ([]byte, error) {
	return nil, errors.New("unexpected open")
}

func (p *blockingRegistrationProtector) Protect(
	_ context.Context,
	_, _, _ string,
	plaintext []byte,
) (string, []byte, error) {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return orchestrator.ResultCodecSealedRowV1, append([]byte(nil), plaintext...), nil
}

func (*blockingRegistrationProtector) Open(
	_ context.Context,
	_, _, _, _ string,
	protected []byte,
) ([]byte, error) {
	return append([]byte(nil), protected...), nil
}
