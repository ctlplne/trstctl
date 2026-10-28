// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/ticketintake"
)

func TestNamedIntakeRemovalAndOwnerMappingKeepTenantAndSweepBoundaries(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	configure := func(name string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok, "named-set-"+name, map[string]any{"name": name, "system": "servicenow", "instance_url": "https://tickets.example.test", "token_ref": servedIntakeTokenRef, "sn_table": "incident", "subject_field": "u_subject", "profile_field": "u_profile", "owner_field": "u_owner_email", "interval_seconds": 3600, "enabled": true})
		if status != http.StatusOK {
			t.Fatalf("configure %s: %d %s", name, status, body)
		}
	}
	for _, name := range []string{"remove-me", "keep-me", "active"} {
		configure(name)
	}
	active, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", "active")
	if err != nil || !found {
		t.Fatal(err)
	}
	h.srv.dispatchTicketSyncJob(ctx, h.tenant, active)
	status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/issuance-requests/intake-schedule?system=servicenow&name=active", tok, "delete-active", nil)
	if status != http.StatusConflict {
		t.Fatalf("deleted an incomplete sweep: %d %s", status, body)
	}
	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body = secretsReqKey(t, h, http.MethodDelete, "/api/v1/issuance-requests/intake-schedule?system=servicenow&name=keep-me", reader, "delete-reader", nil)
	if status != http.StatusForbidden {
		t.Fatalf("reader removal %d %s", status, body)
	}
	for range 2 {
		status, body = secretsReqKey(t, h, http.MethodDelete, "/api/v1/issuance-requests/intake-schedule?system=servicenow&name=remove-me", tok, "delete-exact-name", nil)
		if status != http.StatusNoContent {
			t.Fatalf("remove %d %s", status, body)
		}
	}
	if _, found, err = h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", "remove-me"); err != nil || found {
		t.Fatalf("removed schedule retained: %v %v", found, err)
	}
	if _, found, err = h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", "keep-me"); err != nil || !found {
		t.Fatalf("another name was removed: %v %v", found, err)
	}
	removed := 0
	if err = h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == projections.EventTicketIntakeDeleted {
			removed++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removal retry emitted %d facts", removed)
	}
	const otherTenant = "a2250000-0000-4000-8000-000000000002"
	registerServedTenantID(t, h, otherTenant, "Other named intake tenant")
	otherToken := seedScopedToken(t, h.store, otherTenant, "certs:read")
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/issuance-requests/intake-schedule?system=servicenow&name=keep-me", otherToken, nil)
	var scoped struct {
		Configured bool `json:"configured"`
	}
	if err = json.Unmarshal(body, &scoped); err != nil || status != http.StatusOK || scoped.Configured {
		t.Fatalf("cross-tenant schedule %d %s", status, body)
	}
	for _, name := range []string{"First ambiguity", "Second ambiguity"} {
		if _, err = h.srv.orch.CreateOwner(ctx, h.tenant, "team", name, "ambiguous@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = h.srv.orch.CreateOwner(ctx, otherTenant, "team", "Foreign only", "foreign@example.test"); err != nil {
		t.Fatal(err)
	}
	for i, email := range []string{"ambiguous@example.test", "foreign@example.test"} {
		intent := ticketintake.SyncIntent{Schedule: "keep-me", System: "servicenow", SNTable: "incident", OwnerField: "u_owner_email", SweepID: uuid.NewString(), PageLimit: 100}
		ref := []string{"ambiguous-ticket", "foreign-ticket"}[i]
		report := ticketintake.SyncReport{Schedule: intent.Schedule, System: intent.System, SweepID: intent.SweepID, ObservedAt: time.Now().UTC(), SourceRefs: []string{ref}, Tickets: []ticketintake.Ticket{{SourceRef: ref, Subject: ref + ".example.test", Profile: "tls-server", OwnerEmail: email}}, ReadCount: 1, Complete: true}
		if _, err = h.srv.ingestTicketReport(ctx, h.tenant, "owner-lookup-"+ref, intent, report); err != nil {
			t.Fatal(err)
		}
	}
	requests, err := h.store.ListIssuanceRequests(ctx, h.tenant, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 {
		t.Fatalf("requests %d want 2", len(requests))
	}
	for _, request := range requests {
		if request.OwnerID != "" {
			t.Fatalf("guessed an ambiguous or foreign owner: %+v", request)
		}
	}
}
