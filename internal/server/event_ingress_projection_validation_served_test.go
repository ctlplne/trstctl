// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/webhook"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenantseal"
)

func TestEventIngressValidatesProjectionBeforePublish(t *testing.T) {
	secret := []byte("routing-validation-fixture")
	sink := newServedWebhookSink(t, secret)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client()))}
	})
	const secondTenant = "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h, secondTenant, "Second routing tenant")
	token := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-routing-policies", token, "routing-policy-first", map[string]any{
		"name": "Primary route", "scope_kind": "workspace", "scope_ref": "certificate-lifecycle",
		"default_channels": []string{"webhook"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create first route = %d %s", status, body)
	}
	var first struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &first); err != nil || first.ID == "" {
		t.Fatalf("decode first route: id=%q err=%v", first.ID, err)
	}
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: first.ID, Name: "Second route", ScopeKind: "workspace", ScopeRef: "certificate-lifecycle",
		DefaultChannels: []string{"webhook"},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate := events.Event{ID: uuid.NewString(), Time: time.Now().UTC(), Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: secondTenant, SchemaVersion: 1, Data: data}
	published := false
	_, err = restoreEventIngressAdmissionWithCustody(h.store, func() tenantseal.Access { return publicJournalIngressAccess{} })(t.Context(), candidate,
		func(_ context.Context) (events.Event, error) { published = true; return candidate, nil })
	if err == nil {
		t.Fatal("projection validation accepted a route without a tenant-owned read-model identity")
	}
	if published {
		t.Fatal("projection validation reached publication")
	}
}

func TestEventIngressKeepsInvalidProjectionOutOfHistory(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	const secondTenant = "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h, secondTenant, "Second ingress tenant")
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredAppendAdmission(),
		CustodyValidatedEventIngressOption(h.store, publicJournalIngressAccess{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	policyID := uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Tenant-owned route", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	first := events.Event{ID: uuid.NewString(), Time: time.Now().UTC(), Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: h.tenant, SchemaVersion: 1, Data: data}
	appended, err := log.Append(t.Context(), first)
	if err != nil {
		t.Fatalf("append valid route: %v", err)
	}
	if err := projections.New(h.store).Apply(t.Context(), appended); err != nil {
		t.Fatalf("project valid route: %v", err)
	}
	second := first
	second.ID = uuid.NewString()
	second.TenantID = secondTenant
	if _, err := log.Append(t.Context(), second); err == nil {
		t.Fatal("append accepted a route without a tenant-owned identity")
	}
	deletedData, err := json.Marshal(projections.NotificationRoutingPolicyDeleted{ID: policyID})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := h.log.Append(t.Context(), events.Event{Type: projections.EventNotificationRoutingPolicyDeleted,
		TenantID: h.tenant, Data: deletedData})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(t.Context(), deleted); err != nil {
		t.Fatal(err)
	}
	other, err := h.log.Append(t.Context(), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if retry, err := log.Append(t.Context(), first); err != nil || retry.Sequence != appended.Sequence {
		t.Fatalf("exact event retry: sequence=%d, err=%v", retry.Sequence, err)
	}
	changed := first
	changed.Data = []byte(`{"id":"` + policyID + `","name":"Changed route","scope_kind":"manual"}`)
	if _, err := log.Append(t.Context(), changed); err == nil {
		t.Fatal("changed event retry accepted after the read model moved")
	}
	var count int
	if err := log.Replay(t.Context(), 0, func(e events.Event) error { count++; return nil }); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("retained history has %d events; want the valid event only", count)
	}
}
