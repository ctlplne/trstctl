// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Actual HTTP denial and PG/NATS source, with explicit fixture preparation.
// This proves neither background activation/destruction nor final image proof.
func TestServedPreparingEventKeyRecordsClosedAuthorizationDenial(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	key := testAuditSigningKey(t)
	log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = protection.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "0c83c6ac-97c5-4aa5-911c-ebcdb80313a1"
	registration, err := log.Append(t.Context(), events.Event{Type: "tenant.registered", TenantID: tenant, Data: []byte(`{"name":"preparing fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	requested, err := eventprivacy.NewRequested(tenant, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(requested)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(requested), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, protection.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	const subject = "preparing-reader-private@example.invalid"
	token := seedServedAPIToken(t, t.Context(), st, tenant, subject, []string{string(authz.AccessRead)})
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: protection})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	const canary = "preparing-private-request-canary"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners?private="+canary, bytes.NewBufferString(`{"kind":"team","name":"`+canary+`","email":"fixture-owner@example.invalid"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "preparing-denied-owner")
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusForbidden || response.Header().Get("X-Trstctl-Audit-Status") != "recorded" {
		t.Fatalf("denied request lost truthful audit recording: HTTP=%d audit=%q", response.Code, response.Header().Get("X-Trstctl-Audit-Status"))
	}
	var decisions []events.Event
	if err := log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.Type == "owner.created" {
			t.Fatal("denied owner mutation reached source")
		}
		if event.Type == "authz.decision" {
			decisions = append(decisions, event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 {
		t.Fatalf("authorization audit count=%d, want1", len(decisions))
	}
	event := decisions[0]
	var body map[string]string
	if err := json.Unmarshal(event.Data, &body); err != nil {
		t.Fatal(err)
	}
	if event.TenantID != tenant || event.SchemaVersion != 2 || event.Actor != nil || event.Protection != nil || event.SensitiveErased || len(body) != 3 || body["permission"] != string(authz.OwnersWrite) || body["decision"] != "deny" || body["details_omitted"] != "key_preparing" {
		t.Fatal("preparing audit was not the closed truthful alternate representation")
	}
	head, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error {
		for _, private := range [][]byte{[]byte(subject), []byte(canary), []byte(token)} {
			if bytes.Contains(record.Stored, private) {
				t.Fatal("preparing-state source retained private request or principal material")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
