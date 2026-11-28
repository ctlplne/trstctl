// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenantseal"
)

func TestDirectEventAdmissionChecksReadModelBeforePublication(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	secondTenant := uuid.NewString()
	if err := h.srv.orch.RegisterTenant(ctx, secondTenant, "Second operating tenant", "projection-admission-second"); err != nil {
		t.Fatal(err)
	}
	policyID := uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Shared policy", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredAppendAdmission(),
		CustodyValidatedEventIngressOption(h.store, publicJournalIngressAccess{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	first, err := log.Append(ctx, events.Event{
		Type: projections.EventNotificationRoutingPolicyUpserted, TenantID: h.tenant, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(ctx, first); err != nil {
		t.Fatal(err)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: uuid.NewString(), Name: "", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventNotificationRoutingPolicyUpserted, TenantID: secondTenant, Data: invalid,
	}); err == nil {
		t.Fatal("direct admission published a candidate the read model cannot accept")
	}
	if after, err := log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("source head after rejected candidate = %d, err=%v, want %d", after, err, before)
	}
}

func TestStagedIngressPreservesProtectedControlBoundary(t *testing.T) {
	tenantID := uuid.NewString()
	for _, eventType := range []string{
		projections.EventTenantRegistered,
		projections.EventTenantOffboarded,
		projections.EventTenantEventProtectionRequested,
		projections.EventTenantEventProtectionActivated,
		projections.EventTenantEventProtectionHoldsCleared,
		projections.EventTenantEventProtectionDestroyed,
		audit.EventTypeArchived,
		"tenant.key_domain.sealed",
		"future.read_model.kind",
	} {
		if stagedCoreIngressEligible(events.Event{Type: eventType, TenantID: tenantID}) {
			t.Errorf("specialized event entered core staging: %s", eventType)
		}
	}
	if stagedCoreIngressEligible(events.Event{Type: "secret.created", TenantID: tenantID}) {
		t.Fatal("protected secret entered core staging")
	}
	if !stagedCoreIngressEligible(events.Event{Type: projections.EventOwnerCreated, TenantID: tenantID}) {
		t.Fatal("ordinary core event skipped staged validation")
	}
}

func TestCommittedSourceEventRecoversAfterTenantTransactionRollback(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredAppendAdmission(),
		CustodyValidatedEventIngressOption(h.store, publicJournalIngressAccess{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	policyID := uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Recovered route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("roll back tenant transaction")
	var committed events.Event
	err = h.store.WithTenantEvent(ctx, h.tenant, func(eventCtx context.Context, _ pgx.Tx) error {
		var appendErr error
		committed, appendErr = log.Append(eventCtx, events.Event{
			Type: projections.EventNotificationRoutingPolicyUpserted, TenantID: h.tenant, Data: data,
		})
		if appendErr != nil {
			return appendErr
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("transaction rollback: %v", err)
	}
	if committed.Sequence == 0 {
		t.Fatal("source acknowledgement was not retained")
	}
	if _, err := h.store.GetNotificationRoutingPolicy(ctx, h.tenant, policyID); err == nil {
		t.Fatal("rolled-back projection remained visible")
	}
	projector := projections.New(h.store, projections.WithCanonicalEventSource(log))
	if err := projector.Apply(ctx, committed); err != nil {
		t.Fatalf("replay committed source event: %v", err)
	}
	if _, err := h.store.GetNotificationRoutingPolicy(ctx, h.tenant, policyID); err != nil {
		t.Fatalf("replayed read model: %v", err)
	}
	operations, err := h.store.PendingCommandProjectionOperations(ctx, h.tenant, committed.ID)
	if err != nil || len(operations) != 0 {
		t.Fatalf("replay projection activity: operations=%v err=%v", operations, err)
	}
}

func TestRepeatedEventAdmissionSettlesProjectionActivity(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredAppendAdmission(),
		CustodyValidatedEventIngressOption(h.store, publicJournalIngressAccess{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	policyID := uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Repeated route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: uuid.NewString(), Time: time.Now().UTC(),
		Type: projections.EventNotificationRoutingPolicyUpserted, TenantID: h.tenant,
		SchemaVersion: 1, Data: data}
	for range 2 {
		if _, err := log.Append(ctx, event); err != nil {
			t.Fatalf("repeat event admission: %v", err)
		}
	}
	operations, err := h.store.PendingCommandProjectionOperations(ctx, h.tenant, event.ID)
	if err != nil || len(operations) != 0 {
		t.Fatalf("pending projection activity after repeated admission: operations=%v err=%v", operations, err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != 1 {
		t.Fatalf("source head after repeated admission: head=%d err=%v", head, err)
	}
	if _, err := h.store.GetNotificationRoutingPolicy(ctx, h.tenant, policyID); err != nil {
		t.Fatal(err)
	}
}

func TestFutureEventAdmissionPreservesReplayWithoutCoreReceipt(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredAppendAdmission(),
		CustodyValidatedEventIngressOption(h.store, publicJournalIngressAccess{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	event, err := log.Append(ctx, events.Event{Type: "future.read_model.kind", TenantID: h.tenant,
		Data: []byte(`{"value":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := h.store.ProjectionAppliedEventReceipt(ctx, h.tenant, event.ID, event.Sequence)
	if err != nil || applied {
		t.Fatalf("future event has a core receipt: applied=%t err=%v", applied, err)
	}
}

func TestAttachedProjectorValidatesDirectEvent(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	runtime := &eventProtectionRuntime{}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredAppendAdmission(),
		restoreEventIngressOptionWithCustody(h.store,
			func() tenantseal.Access { return publicJournalIngressAccess{} }, runtime.admissionProjector))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime.attachAdmissionProjector(projections.New(h.store, projections.WithCanonicalEventSource(log)))
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: uuid.NewString(), Name: "", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: h.tenant, Data: data}); err == nil {
		t.Fatal("attached projector accepted an unprojectable event")
	}
	if head, err := log.LastSequence(ctx); err != nil || head != 0 {
		t.Fatalf("source advanced before attached projection: head=%d err=%v", head, err)
	}
}
