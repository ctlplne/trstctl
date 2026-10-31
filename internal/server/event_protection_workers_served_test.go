// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Actual configured runtime, SQL-backed outbox, bounded dispatcher loop, current
// file custody and signed receipt. The request is an explicit source fixture;
// this is not the public enable route or a separate-process signer proof.
func TestEventProtectionRuntimeExecutesPreparationAndDestructionOnBoundedWorkers(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	key := testAuditSigningKey(t)
	log, custody, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "2fc9830e-9d77-44a0-ac3d-52f22525baa2"
	const neighbor = "63201533-ce9d-450f-8bc9-022cff22cbcc"
	register := func(id string) events.Event {
		t.Helper()
		event, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: id, Data: []byte(`{"name":"worker fixture"}`)})
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	registration := register(tenant)
	register(neighbor)
	request, err := eventprivacy.NewRequested(tenant, registration.ID, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, custody.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	ref := eventprotect.KeyRef{TenantID: tenant, ID: request.KeyID}
	keyFile := filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, tenant, request.KeyID+".key")
	if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("request fixture itself provisioned material")
	}
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: custody})
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); srv.RunDispatcher(workerCtx) }()
	defer func() { cancel(); <-done; _ = srv.Shutdown(t.Context()) }()
	wait := func(label string, visit func() bool) {
		t.Helper()
		deadline := time.NewTimer(12 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			if visit() {
				return
			}
			select {
			case <-deadline.C:
				t.Fatalf("%s did not complete through the real bounded worker", label)
			case <-tick.C:
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
		}
	}
	wait("key activation", func() bool {
		life, err := custody.policy.LatestLifetime(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		if life.Activation == nil {
			return false
		}
		creation, err := custody.custody.CreationEvidence(t.Context(), ref)
		if store.IsBusy(err) {
			return false
		}
		if err != nil || creation.Digest() != life.Activation.Body.Creation.Digest() {
			t.Fatalf("activation lacks independent material: %v", err)
		}
		return eventKeyDeliverySettled(t, st, tenant, store.EventKeyPreparationOutboxKey(request.KeyID), false)
	})
	creation, err := custody.custody.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	life, err := custody.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Activation == nil || life.Activation.Body.Creation.Digest() != creation.Digest() {
		t.Fatalf("activation lacks exact independently read key identity: %v", err)
	}
	owner, err := srv.orch.CreateOwner(t.Context(), tenant, "team", "Worker owner", "worker-private@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	other, err := srv.orch.CreateOwner(t.Context(), neighbor, "team", "Neighbor owner", "neighbor-private@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	var protected events.Event
	head, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := log.ReplayTenantTypesThrough(t.Context(), tenant, 1, head, []string{projections.EventOwnerCreated}, func(event events.Event) error {
		if bytes.Contains(event.Data, []byte(owner.ID)) {
			protected = event
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if protected.ID == "" || protected.Protection == nil {
		t.Fatal("activated worker lifetime did not protect real subsequent owner data")
	}
	if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error {
		if bytes.Contains(record.Stored, []byte("worker-private@example.invalid")) {
			t.Fatal("raw protected source contains private owner data")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registration.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetTenant(t.Context(), tenant); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("offboarding did not delete actual tenant read state")
	}
	life, err = custody.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Offboard == nil {
		t.Fatalf("offboarding source is missing: %v", err)
	}
	destruction, err := eventprivacy.NewDestructionRequest(life)
	if err != nil {
		t.Fatal(err)
	}
	if !time.Now().UTC().Before(destruction.NotBefore) {
		t.Fatal("fixture failed to observe the real pre-deadline state")
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("key removed before original retention deadline: %v", err)
	}
	wait("signed key destruction", func() bool {
		life, err := custody.policy.LatestLifetime(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		if life.Completion == nil {
			return false
		}
		receipt, erased, err := custody.custody.DestructionReceipt(t.Context(), ref)
		if store.IsBusy(err) {
			return false
		}
		if err != nil || !erased || receipt != life.Completion.JWS {
			t.Fatalf("source completion lacks independent signed absence: %v", err)
		}
		return eventKeyDeliverySettled(t, st, tenant, store.EventKeyDestructionOutboxKey(destruction.OperationID), true)
	})
	receipt, erased, err := custody.custody.DestructionReceipt(t.Context(), ref)
	if err != nil || !erased || receipt == "" {
		t.Fatalf("completion lacks current independent receipt/absence: %v", err)
	}
	claims, err := eventprotect.VerifyDestructionReceipt(key.JWKS(), receipt)
	if err != nil || claims.Request != destruction || claims.RemovedAt.Before(destruction.NotBefore) {
		t.Fatalf("receipt differs from exact retained lifetime/deadline: %v", err)
	}
	if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("destruction completion retained recoverable material")
	}
	actual, found, err := log.EventByID(t.Context(), protected.ID)
	if err != nil || !found || !actual.SensitiveErased || len(actual.Data) != 0 || actual.Actor != nil {
		t.Fatalf("actual worker destruction did not erase protected reads: %v", err)
	}
	got, err := st.GetOwner(t.Context(), neighbor, other.ID)
	if err != nil || got.Email != other.Email {
		t.Fatalf("neighbor was changed by another tenant's worker: %v", err)
	}
	if _, err := st.GetTenant(t.Context(), tenant); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("completion recreated the removed tenant")
	}
}

// The same selected boxes also execute through the bounded shutdown drain;
// stopping the live ticker must not strand either event-key destination.
func TestEventProtectionRuntimePreparesAndDestroysThroughDrain(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	key := testAuditSigningKey(t)
	log, custody, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "3de09948-41c9-4b3f-9c72-21c328eb44ca"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"drain fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewRequested(tenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, custody.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: custody})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	life, err := custody.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Activation == nil {
		t.Fatalf("drain stranded preparation: %v", err)
	}
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registration.ID}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	life, err = custody.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Completion == nil {
		t.Fatalf("drain stranded post-delete destruction: %v", err)
	}
	receipt, erased, err := custody.custody.DestructionReceipt(t.Context(), eventprotect.KeyRef{TenantID: tenant, ID: request.KeyID})
	if err != nil || !erased || receipt != life.Completion.JWS {
		t.Fatalf("drain completion lacks independent signed absence: %v", err)
	}
}

// Observe operational settlement as well as immutable source publication. A
// verified completed destruction may already have removed its exact intent.
func eventKeyDeliverySettled(t *testing.T, st *store.Store, tenant, idempotency string, allowRemoved bool) bool {
	t.Helper()
	var settled bool
	err := st.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT status='delivered' AND cardinality(receiver_pending_ids)=0 FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tenant, idempotency).Scan(&settled)
	})
	if store.IsBusy(err) {
		return false
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return allowRemoved
	}
	if err != nil {
		t.Fatal(err)
	}
	return settled
}
