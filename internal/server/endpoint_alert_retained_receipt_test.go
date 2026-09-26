// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// Real PG/NATS preserve the receipt after its delivered outbox row is removed
// for retention. The channel is a recording test double, not OpsGenie proof.
func TestEndpointAlertRetainedReceiptCannotPoisonNewIncident(t *testing.T) {
	channel := &flakyNotificationChannel{}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{channel}
	})
	ctx := t.Context()
	const endpoint = "retained-receipt-endpoint"
	legacyKey := "endpoint-verify:" + endpoint + ":relay::"
	legacy := notify.Alert{Kind: notify.KindEndpointUnreachable, TenantID: h.tenant,
		EndpointAddress: "db.example.test:5432", Subject: "db.example.test:5432",
		Vantage: "relay", Severity: notify.AlertSeverityWarning, Detail: "older connection failure"}
	enqueue := func(alert notify.Alert) int64 {
		t.Helper()
		payload, err := json.Marshal(alert)
		if err != nil {
			t.Fatal(err)
		}
		var id int64
		err = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			var err error
			id, err = h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: h.tenant,
				Destination: notify.DestinationVerification, IdempotencyKey: legacyKey, Payload: payload})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	firstID := enqueue(legacy)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := h.store.GetNotificationOutbox(ctx, h.tenant, firstID)
	if err != nil || first.OutboxStatus != "delivered" || channel.deliveries() != 1 {
		t.Fatalf("initial receiver effect missing: %+v %v count=%d", first, err, channel.deliveries())
	}
	// Simulate retention of this one completed transport row. Its immutable
	// notification.delivery.recorded event and SQL receipt remain untouched.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2 AND status='delivered'`, h.tenant, firstID)
		if err == nil && tag.RowsAffected() != 1 {
			return fmt.Errorf("retained transport rows removed=%d", tag.RowsAffected())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	legacy.Detail = "new connection failure with different wording"
	changedID := enqueue(legacy)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	changed, err := h.store.GetNotificationOutbox(ctx, h.tenant, changedID)
	if err != nil || changed.LastError != "notification_receipt_binding_conflict" || changed.DeliveredAt != nil {
		t.Errorf("conflicting retained command lacks an actionable safe class: %+v %v", changed, err)
	}
	if channel.deliveries() != 1 {
		t.Fatal("changed command reused or bypassed the retained receipt")
	}
	token := seedScopedToken(t, h.store, h.tenant, "notifications:read")
	status, body := secretsReq(t, h, http.MethodGet, fmt.Sprintf("/api/v1/notifications/%d", changedID), token, nil)
	var detail struct {
		LastError string `json:"last_error"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || detail.LastError != "notification_receipt_binding_conflict" {
		t.Errorf("served operator diagnostic: status=%d body=%s", status, body)
	}
	observation := projections.EndpointVerificationObserved{EndpointID: endpoint,
		Address: legacy.EndpointAddress, Vantage: legacy.Vantage, Detail: legacy.Detail, ObservedAt: time.Now().UTC()}
	record := func(key string) {
		t.Helper()
		if err := h.srv.orch.RecordEndpointVerificationWithEventID(ctx, h.tenant,
			orchestrator.DiscoveryRelayEventID(h.tenant, key, endpoint), observation); err != nil {
			t.Fatal(err)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	record("version2-first-probe")
	if channel.deliveries() != 2 {
		t.Fatalf("new versioned incident blocked by legacy receipt: deliveries=%d", channel.deliveries())
	}
	observation.Detail = "another raw error on the same outage"
	observation.ObservedAt = observation.ObservedAt.Add(time.Second)
	record("version2-repeat-probe")
	if channel.deliveries() != 2 {
		t.Fatalf("same versioned incident sent again: deliveries=%d", channel.deliveries())
	}
	var receipts int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_delivery_receipts WHERE tenant_id=$1 AND destination='notification.verification'`, h.tenant).Scan(&receipts)
	}); err != nil {
		t.Fatal(err)
	}
	if receipts != 2 {
		t.Fatalf("legacy and new delivery histories did not remain separate: %d", receipts)
	}
}
