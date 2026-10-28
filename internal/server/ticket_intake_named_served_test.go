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
)

func TestServedNamedTicketIntakesKeepTheirSourcesAndMapTenantOwners(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "owners:write")
	ownerID := servedCreateID(t, h, tok, "intake-owner", "/api/v1/owners", map[string]any{"kind": "team", "name": "Operations", "email": "ops@example.test"})
	sources := []struct{ system, name, table, project, key string }{
		{"servicenow", "incidents", "incident", "", "row1"},
		{"servicenow", "requests", "sc_req_item", "", "row1"},
		{"jira", "operations", "", "OPS", "OPS-1"},
		{"jira", "platform", "", "PLAT", "PLAT-1"},
	}
	for _, source := range sources {
		input := map[string]any{"system": source.system, "name": source.name, "instance_url": "https://tickets.example.test", "token_ref": servedIntakeTokenRef, "sn_table": source.table, "jira_project": source.project, "subject_field": "u_subject", "profile_field": "u_profile", "owner_field": "u_owner_email", "interval_seconds": 3600, "enabled": true}
		status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok, "configure-"+source.name, input)
		if status != http.StatusOK {
			t.Fatalf("save %s = %d %s", source.name, status, body)
		}
	}
	for _, source := range sources {
		path := "/api/v1/issuance-requests/intake-schedule?system=" + source.system + "&name=" + source.name
		status, body := secretsReq(t, h, http.MethodGet, path, tok, nil)
		var got struct {
			Name       string `json:"name"`
			Table      string `json:"sn_table"`
			Project    string `json:"jira_project"`
			OwnerField string `json:"owner_field"`
		}
		if err := json.Unmarshal(body, &got); err != nil || status != http.StatusOK || got.Name != source.name || got.Table != source.table || got.Project != source.project || got.OwnerField != "u_owner_email" {
			t.Fatalf("schedule %s was overwritten: %d %s (%v)", source.name, status, body, err)
		}
	}
	due, err := h.store.TicketIntakeDueSchedules(ctx, h.tenant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 4 {
		t.Fatalf("due schedules %d want 4", len(due))
	}
	for _, schedule := range due {
		h.srv.dispatchTicketSyncJob(ctx, h.tenant, schedule)
	}
	for i, source := range sources {
		var payload []byte
		var key string
		err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT payload,idempotency_key FROM outbox WHERE tenant_id=$1 AND destination='ticket.sync' AND convert_from(payload,'UTF8')::jsonb->>'system'=$2 AND convert_from(payload,'UTF8')::jsonb->>'schedule'=$3`, h.tenant, source.system, source.name).Scan(&payload, &key)
		})
		if err != nil {
			t.Fatalf("independent %s relay job: %v", source.name, err)
		}
		var intent map[string]any
		if err := json.Unmarshal(payload, &intent); err != nil {
			t.Fatal(err)
		}
		subject := fmt.Sprintf("named-%d.example.test", i)
		ownerEmail := "ops@example.test"
		if i == 3 {
			ownerEmail = "hidden-or-unmapped@example.test"
		}
		report := map[string]any{"schedule": source.name, "system": source.system, "sweep_id": intent["sweep_id"], "observed_at": time.Now().UTC(), "source_refs": []string{"1"}, "tickets": []map[string]any{{"source_ref": "1", "external_key": source.key, "subject": subject, "profile": "tls-server", "requester": "requester@example.test", "owner_email": ownerEmail}}, "read_count": 1, "complete": true}
		if source.system == "servicenow" {
			report["source_refs"] = []string{source.key}
			report["tickets"].([]map[string]any)[0]["source_ref"] = source.key
		}
		// A valid observation for one job cannot claim another schedule's cursor.
		report["schedule"] = "another-schedule"
		if err := h.srv.recordTicketSync(ctx, h.tenant, "named-relay", key, payload, mustJSON(t, report)); err == nil {
			t.Fatal("cross-schedule report was accepted")
		}
		report["schedule"] = source.name
		if err := h.srv.recordTicketSync(ctx, h.tenant, "named-relay", key, payload, mustJSON(t, report)); err != nil {
			t.Fatalf("%s report: %v", source.name, err)
		}
	}
	requests, err := h.store.ListIssuanceRequests(ctx, h.tenant, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 4 {
		t.Fatalf("requests %d want 4", len(requests))
	}
	for _, request := range requests {
		want := ownerID
		if request.Subject == "named-3.example.test" {
			want = ""
		}
		if request.OwnerID != want {
			t.Fatalf("%s owner %q want %q", request.Subject, request.OwnerID, want)
		}
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/issuance-requests/intake-schedules", tok, nil)
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil || status != http.StatusOK || len(list.Items) != 4 {
		t.Fatalf("list = %d %s (%v)", status, body, err)
	}
}
