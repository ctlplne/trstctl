// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type eventProtectionOffboardFixture struct {
	store        *store.Store
	log          *events.Log
	projector    *projections.Projector
	keys         *eventprotect.FileAuthority
	policy       *eventprivacy.SourcePolicy
	registration events.Event
	activation   events.Event
	record       func(context.Context, events.Event) (events.Event, error)
}

func newEventProtectionOffboardFixture(t *testing.T) eventProtectionOffboardFixture {
	t.Helper()
	s := newStore(t)
	base := t.TempDir()
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{
		Directory: filepath.Join(base, "independent-keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: s,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	policy := &eventprivacy.SourcePolicy{}
	admission := &eventprivacy.SourceAdmission{Guard: s, Custody: keys}
	reader := &eventprivacy.SourceKeys{Custody: keys}
	receiver := &eventprivacy.PreparationReceiver{Claims: s, Guard: s, Custody: keys}
	verifier := &eventprivacy.ActivationVerifier{Custody: keys}
	p := projections.New(s, projections.WithEventProtectionActivationVerifier(verifier), projections.WithEventProtectionOffboardPolicy(policy))
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")},
		func(log *events.Log) {
			policy.Log = log
			admission.Policy.Log, reader.Policy.Log, receiver.Policy.Log, verifier.Policy.Log = log, log, log, log
		},
		events.WithEventProtection(events.EventProtection{Admission: admission, Keys: reader}),
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)), events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	record := func(ctx context.Context, next events.Event) (events.Event, error) {
		var result events.Event
		err := s.WithTenant(ctx, next.TenantID, func(tx pgx.Tx) error {
			var err error
			result, err = log.Append(ctx, next)
			if err != nil {
				return err
			}
			if next.Type == projections.EventTenantRegistered || next.Type == projections.EventTenantOffboarded {
				return p.ApplyTenantLifecycleTx(ctx, tx, result)
			}
			return p.ApplyTx(ctx, tx, result)
		})
		return result, err
	}
	receiver.Record = func(ctx context.Context, event events.Event) (events.Event, error) {
		return record(events.ContextWithoutActor(ctx), event)
	}
	registration, err := record(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("fixture-A")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenantB, Data: tenantRegistered("fixture-B")}); err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewRequested(tenantA, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenantA, Data: wire}); err != nil {
		t.Fatal(err)
	}
	box := orchestrator.NewOutbox(s, orchestrator.WithTenantServiceCheck(s.RequireLiveTenantService))
	handler := orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
		var command store.EventKeyPreparationCommand
		if err := json.Unmarshal(message.Payload, &command); err != nil {
			return err
		}
		return receiver.Prepare(ctx, store.EventKeyPreparationClaim{ID: message.ID, AttemptID: message.ReceiverAttemptID, Attempts: message.Attempts, Command: command})
	})
	if worked, err := box.DispatchOneScoped(t.Context(), handler, orchestrator.DestinationScope{IncludePrefixes: []string{store.EventKeyPreparationDestination}}); err != nil || !worked {
		t.Fatalf("activate fixture through committed receiver: %v", err)
	}
	activation, found, err := log.EventByID(t.Context(), request.KeyID)
	if err != nil || !found {
		t.Fatalf("activation absent: %v", err)
	}
	return eventProtectionOffboardFixture{store: s, log: log, projector: p, keys: keys, policy: policy, registration: registration, activation: activation, record: record}
}

func TestEventProtectionOffboardIntentIsAtomicAcrossLiveAndRetainedProjection(t *testing.T) {
	f := newEventProtectionOffboardFixture(t)
	ctx := t.Context()
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := f.record(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenant, Data: ownerCreated("aaaaaaaa-0000-0000-0000-000000000001", "private-owner")}); err != nil {
			t.Fatal(err)
		}
	}
	var offboard events.Event
	rollback := errors.New("fixture SQL interruption after source append")
	if err := f.store.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var err error
		offboard, err = f.log.Append(ctx, events.Event{ID: projections.TenantOffboardEventID(tenantA, f.registration.ID), Type: projections.EventTenantOffboarded, TenantID: tenantA, Data: []byte(`{"rows_deleted":0}`)})
		if err != nil {
			return err
		}
		if err := f.projector.ApplyTenantLifecycleTx(ctx, tx, offboard); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	count := func(tenant, table string) int {
		t.Helper()
		var n int
		if err := f.store.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(tenantA, "owners") != 1 || count(tenantA, "tenants") != 1 {
		t.Fatal("rolled-back relational erase leaked")
	}
	if err := f.store.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyDestructionDestination).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatal("source append without committed SQL leaked destructive intent")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Catchup may encounter the old exact activation after source has advanced
	// to offboard. This is readback/settlement, never permission to provision.
	if err := f.projector.Apply(ctx, f.activation); err != nil {
		t.Fatalf("later offboard prevented exact historical activation readback: %v", err)
	}
	if err := f.store.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return f.projector.ApplyTenantLifecycleTx(ctx, tx, offboard)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.projector.ApplyRetainedTenantLifecycle(ctx, offboard); err != nil {
		t.Fatal(err)
	}
	if err := f.projector.Apply(ctx, offboard); err != nil {
		t.Fatal(err)
	}
	if count(tenantA, "owners") != 0 || count(tenantA, "tenants") != 0 || count(tenantA, "outbox") != 1 || count(tenantB, "owners") != 1 || count(tenantB, "tenants") != 1 {
		t.Fatal("replayed erase lost its sole public intent or affected the neighbor")
	}
	command, protected, err := f.policy.EventKeyDestructionForOffboard(ctx, offboard)
	if err != nil || !protected {
		t.Fatal(err)
	}
	if _, err := f.keys.CreationEvidence(ctx, command.Ref); err != nil {
		t.Fatalf("intent projection performed premature key I/O: %v", err)
	}
}
