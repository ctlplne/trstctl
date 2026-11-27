// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestIngressDoesNotWaitOnCommandOwnedReadModelRow(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	policyID := uuid.NewString()
	initialData, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Current route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := h.log.Append(t.Context(), events.Event{Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: h.tenant, Data: initialData})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredAppendAdmission(),
		CustodyValidatedEventIngressOption(h.store, publicJournalIngressAccess{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	updatedData, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Updated route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var updated events.Event
	err = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var lockedID string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM notification_routing_policies WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			h.tenant, policyID).Scan(&lockedID); err != nil {
			return err
		}
		var appendErr error
		updated, appendErr = log.Append(ctx, events.Event{Type: projections.EventNotificationRoutingPolicyUpserted,
			TenantID: h.tenant, Data: updatedData})
		return appendErr
	})
	if err != nil {
		t.Fatalf("append while command owns its read-model row: %v", err)
	}
	if err := projections.New(h.store).Apply(t.Context(), updated); err != nil {
		t.Fatal(err)
	}
	policy, err := h.store.GetNotificationRoutingPolicy(t.Context(), h.tenant, policyID)
	if err != nil || policy.Name != "Updated route" {
		t.Fatalf("updated route: name=%q, err=%v", policy.Name, err)
	}
}
