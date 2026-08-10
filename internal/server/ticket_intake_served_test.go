// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/ticketintake"
)

// I3's intake, end to end: a ServiceNow ticket becomes an issuance request
// with the existing lifecycle deciding it — idempotently by ticket reference,
// with unmappable tickets counted rather than guessed at.

// servedIntakeTokenRef is a secret-store pointer redeemed by the relay.
const servedIntakeTokenRef = "secret://itsm/intake-token" // #nosec G101 -- credential reference (secret store pointer), no credential value present (CWE-798)

func TestServedTicketIntakeOpensRequestsIdempotently(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")

	status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok,
		"intake-1", map[string]any{
			"system": "servicenow", "instance_url": "https://servicenow.internal.example", "token_ref": servedIntakeTokenRef,
			"sn_table": "sc_req_item", "query": "state=1",
			"subject_field": "u_subject", "profile_field": "u_profile",
			"requester_field": "opened_by", "justification_field": "short_description",
			"interval_seconds": 3600, "enabled": true,
		})
	if status != http.StatusOK {
		t.Fatalf("configure intake: %d %s", status, out)
	}
	// A table outside the closed set is refused by name.
	status, out = secretsReqKey(t, h, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok,
		"intake-bad", map[string]any{
			"system": "servicenow", "instance_url": "https://servicenow.internal.example", "token_ref": servedIntakeTokenRef,
			"sn_table": "sys_user_password", "subject_field": "a", "profile_field": "b",
			"interval_seconds": 3600, "enabled": true,
		})
	if status != http.StatusBadRequest || !strings.Contains(string(out), "sn_table") {
		t.Fatalf("an arbitrary table = %d %s; an unbounded name would aim the intake token at "+
			"records that are not tickets", status, out)
	}

	sched, found, err := h.store.GetTicketIntakeSchedule(t.Context(), h.tenant, "servicenow")
	if err != nil || !found {
		t.Fatalf("schedule not persisted: %v %v", found, err)
	}
	intent := ticketSyncIntent(sched)
	h.srv.dispatchTicketSyncJob(t.Context(), h.tenant, sched)
	var jobs int
	var role string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*), max(required_agent_role) FROM outbox WHERE tenant_id = $1 AND destination = 'ticket.sync'`, h.tenant).Scan(&jobs, &role)
	}); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || role != "network" {
		t.Fatalf("ticket intake dispatched %d jobs with role %q, want one durable network-relay job", jobs, role)
	}
	report := ticketintake.SyncReport{ObservedAt: time.Now().UTC(), Tickets: []ticketintake.Ticket{
		{SysID: "tick-1", Subject: "payments.example.test", Profile: "tls-server", Requester: "Dana Ops", Justification: "cert for payments"},
		{SysID: "tick-2", Profile: "tls-server", Justification: "no subject mapped"},
	}}
	res, err := h.srv.ingestTicketReport(t.Context(), h.tenant, "ticket-sync-1", intent, report)
	if err != nil {
		t.Fatal(err)
	}
	if res.Read != 2 || res.Opened != 1 || res.Skipped != 1 {
		t.Fatalf("intake = %+v, want read 2, opened 1, skipped 1.\n\n"+
			"The empty-subject ticket must be SKIPPED AND COUNTED, never guessed at: an intake "+
			"that opened requests from prose would fill the approval queue with noise", res)
	}

	// The request exists, carries its origin and ticket, and the requester
	// came from the mapped field's DISPLAY value.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/issuance-requests", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list requests: %d %s", status, body)
	}
	var list struct {
		Items []struct {
			Subject   string `json:"subject"`
			Profile   string `json:"profile"`
			Requester string `json:"requester"`
			Origin    string `json:"origin"`
			TicketRef string `json:"ticket_ref"`
			Status    string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("requests = %d, want 1: %s", len(list.Items), body)
	}
	req := list.Items[0]
	if req.Subject != "payments.example.test" || req.Profile != "tls-server" ||
		req.Origin != "servicenow" || req.TicketRef != "sc_req_item:tick-1" ||
		req.Requester != "Dana Ops" || req.Status != "requested" {
		t.Fatalf("request = %+v; the ticket's mapped fields are the request, and the display "+
			"value is the requester a human can route an approval to", req)
	}

	// A second sweep sees the same ticket: one ticket, one request.
	res, err = h.srv.ingestTicketReport(t.Context(), h.tenant, "ticket-sync-1", intent, report)
	if err != nil {
		t.Fatal(err)
	}
	if res.Opened != 0 || res.Already != 1 {
		t.Fatalf("second sweep = %+v; a re-seen ticket must not open a second request", res)
	}

	// Denial is the ANSWER to that ticket: after a deny, the next sweep still
	// opens nothing.
	var reqID string
	{
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/issuance-requests", tok, nil)
		if status != http.StatusOK {
			t.Fatal("list failed")
		}
		var l struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &l); err != nil || len(l.Items) != 1 {
			t.Fatalf("relist: %v %s", err, body)
		}
		reqID = l.Items[0].ID
	}
	dtok := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")
	if status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+reqID+"/deny", dtok, "deny-1",
		map[string]any{"reason": "wrong profile for this subject"}); status != http.StatusOK {
		t.Fatalf("deny: %d %s", status, body)
	}
	res, err = h.srv.ingestTicketReport(t.Context(), h.tenant, "ticket-sync-1", intent, report)
	if err != nil {
		t.Fatal(err)
	}
	if res.Opened != 0 {
		t.Fatalf("after a denial the sweep reopened the ticket: %+v.\n\n"+
			"The denial WAS the answer to that ticket; a fresh ask needs a fresh ticket, or every "+
			"'no' silently becomes 'ask me again every interval'", res)
	}
}
