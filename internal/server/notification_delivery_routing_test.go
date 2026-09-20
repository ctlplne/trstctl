// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestServedRenewalDeliveryRetainsSelectedRouteAfterPolicyDeletion(t *testing.T) {
	selected := &namedFlakyNotificationChannel{name: "slack"}
	unselected := &namedFlakyNotificationChannel{name: "webhook"}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{selected, unselected}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-routing-policies", tok, "receipt-route-create", map[string]any{
		"name": "Renewal owner route", "scope_kind": "asset", "scope_ref": "identity/payments",
		"channels_by_severity": map[string][]string{"warning": {"slack"}}, "default_channels": []string{"slack"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create route: %d %s", status, body)
	}
	var policy struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &policy); err != nil {
		t.Fatal(err)
	}
	alert, _ := json.Marshal(notify.Alert{
		Kind: notify.KindRenewalFailed, TenantID: h.tenant, IdentityID: "payments",
		CertificateID: "historical-leaf", Subject: "payments.example.test", Severity: notify.AlertSeverityWarning,
	})
	var notificationID int64
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		var err error
		notificationID, err = h.srv.outbox.Enqueue(t.Context(), tx, orchestrator.Entry{
			TenantID: h.tenant, Destination: notify.DestinationRenewalFailure,
			IdempotencyKey: "receipt-renewal-failure", Payload: alert,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if selected.deliveries() != 1 || unselected.deliveries() != 0 {
		t.Fatalf("identity route was displaced by certificate metadata: selected=%d other=%d", selected.deliveries(), unselected.deliveries())
	}
	path := fmt.Sprintf("/api/v1/notifications/%d", notificationID)
	readReceipt := func() json.RawMessage {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, path, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read notification: %d %s", status, body)
		}
		var response struct {
			Deliveries []json.RawMessage `json:"deliveries"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Deliveries) != 1 {
			t.Fatalf("delivery receipts: %s", body)
		}
		return response.Deliveries[0]
	}
	before := readReceipt()
	var receipt struct {
		Channel  string `json:"channel"`
		Source   string `json:"routing_source"`
		PolicyID string `json:"routing_policy_id"`
		Scope    string `json:"routing_policy_scope"`
		Digest   string `json:"routing_policy_digest"`
	}
	if err := json.Unmarshal(before, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Channel != "slack" || receipt.Source != "inherited_policy" || receipt.PolicyID != policy.ID || receipt.Scope != "asset" || len(receipt.Digest) != 64 {
		t.Fatalf("selected route not retained: %s", before)
	}
	status, body = secretsReqKey(t, h, http.MethodDelete, "/api/v1/notification-routing-policies/"+policy.ID, tok, "receipt-route-delete", nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete policy: %d %s", status, body)
	}
	if after := readReceipt(); string(after) != string(before) {
		t.Fatalf("policy deletion rewrote receipt: before=%s after=%s", before, after)
	}
	writerOnly := seedScopedToken(t, h.store, h.tenant, "notifications:write")
	status, body = secretsReq(t, h, http.MethodGet, path, writerOnly, nil)
	if status != http.StatusForbidden {
		t.Fatalf("receipt read without permission: %d %s", status, body)
	}
}
