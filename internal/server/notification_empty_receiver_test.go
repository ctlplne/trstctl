// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/webhook"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestNotificationWithoutReceiverRemainsUndeliveredUntilConfigured(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "notifications:read")
	payload, err := json.Marshal(notify.Alert{Kind: notify.KindUnexpectedIssuance, TenantID: h.tenant, Subject: "unrouted.served.test", Severity: notify.AlertSeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	const key = "empty-receiver-regression"
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := h.srv.outbox.Enqueue(t.Context(), tx, orchestrator.Entry{TenantID: h.tenant, Destination: notify.DestinationCTLog, IdempotencyKey: key, Payload: payload})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	var status, lastError string
	var deliveredAt *time.Time
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT status,COALESCE(last_error,''),delivered_at FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, key).Scan(&status, &lastError, &deliveredAt)
	}); err != nil {
		t.Fatal(err)
	}
	if status == "delivered" || deliveredAt != nil || !strings.Contains(lastError, "notification_receiver_not_configured") {
		t.Fatalf("empty fan-out claimed delivery: status=%s delivered=%v error=%q", status, deliveredAt, lastError)
	}
	code, body := secretsReq(t, h, http.MethodGet, "/api/v1/notifications", token, nil)
	if code != http.StatusOK || strings.Contains(string(body), `"status":"sent"`) || !strings.Contains(string(body), "notification_receiver_not_configured") {
		t.Fatalf("served inbox hid missing receiver: %d %s", code, body)
	}
	secret := []byte("empty-receiver-regression-secret")
	sink := newServedWebhookSink(t, secret)
	h.srv.notifications.Register(webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client())))
	// Make the existing retry due now; preserve its key, payload and attempt count.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE outbox SET next_attempt_at=now() WHERE tenant_id=$1 AND idempotency_key=$2 AND status='pending'`, h.tenant, key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReq(t, h, http.MethodGet, "/api/v1/notifications", token, nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"status":"sent"`) {
		t.Fatalf("configured retry did not deliver: %d %s", code, body)
	}
	if sink.Accepted() != 1 || sink.LastAlert().Subject != "unrouted.served.test" {
		t.Fatalf("receiver did not accept the original alert exactly once: count=%d alert=%+v", sink.Accepted(), sink.LastAlert())
	}
	var receipts int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM notification_delivery_receipts WHERE tenant_id=$1`, h.tenant).Scan(&receipts)
	}); err != nil || receipts != 1 {
		t.Fatalf("actual receiver receipts=%d error=%v", receipts, err)
	}
}
