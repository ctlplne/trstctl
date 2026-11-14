// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/ticketintake"
)

// p13l2Catalog is a ServiceNow stand-in for catalog approvals: requested
// items and requests read by sys_id with their approval and state.
type p13l2Catalog struct {
	mu        sync.Mutex
	approvals map[string]map[string]string // table -> sys_id -> approval
	numbers   map[string]string            // sys_id -> number
}

func (s *p13l2Catalog) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		table := strings.TrimPrefix(r.URL.Path, "/api/now/table/")
		rows, ok := s.approvals[table]
		if r.Method != http.MethodGet || !ok {
			t.Errorf("unexpected ServiceNow call: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		out := []map[string]string{}
		for _, id := range strings.Split(strings.TrimPrefix(r.URL.Query().Get("sysparm_query"), "sys_idIN"), ",") {
			if approval, ok := rows[id]; ok {
				out = append(out, map[string]string{"sys_id": id, "number": s.numbers[id], "approval": approval, "state": "1"})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": out})
	})
}

// P13-L2: a catalog requested item or request approved in ServiceNow
// approves the trstctl request intake opened from it, and a rejected one
// denies it, as a change request does: each catalog schedule's approval read
// runs through the production relay with its own token, and the decision is
// attributed to the item's or request's own table and number.
func TestServedCatalogApprovalsDecideTheirRequestsP13L2(t *testing.T) {
	sn := &p13l2Catalog{
		approvals: map[string]map[string]string{"sc_req_item": {"ri0001": "requested"}, "sc_request": {"rq0002": "requested"}},
		numbers:   map[string]string{"ri0001": "RITM0010001", "rq0002": "REQ0010002"},
	}
	stand := httptest.NewTLSServer(sn.handler(t))
	t.Cleanup(stand.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindTicketStatus})
	ctx := t.Context()
	const tokenName = "p13l2-intake-token" // #nosec G101 -- the name of a test-only secret, not a credential (CWE-798)
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, tokenName, []byte("servicenow-catalog-token"))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, tokenName, sealed)
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	for name, table := range map[string]string{"items": "sc_req_item", "requests": "sc_request"} {
		if status, out := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok, "p13l2-"+name,
			map[string]any{"system": "servicenow", "name": name, "instance_url": stand.URL, "token_ref": "secret://" + tokenName,
				"sn_table": table, "subject_field": "u_subject", "profile_field": "u_profile", "requester_field": "requested_for",
				"interval_seconds": 3600, "enabled": true}); status != http.StatusOK {
			t.Fatalf("configure the %s intake: %d %s", name, status, out)
		}
	}
	type opened struct{ schedule, ref, subject, requester string }
	for _, o := range []opened{{"items", "ri0001", "catalog-item.example.test", "dana@example.test"}, {"requests", "rq0002", "catalog-request.example.test", "lee@example.test"}} {
		sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", o.schedule)
		if err != nil || !found {
			t.Fatalf("schedule %s: %v %v", o.schedule, found, err)
		}
		intent := ticketSyncIntent(sched)
		expected := 1
		if _, err := h.srv.ingestTicketReport(ctx, h.tenant, "p13l2-sync-"+o.schedule, intent, ticketintake.SyncReport{
			Schedule: o.schedule, System: "servicenow", SweepID: intent.SweepID, ObservedAt: time.Now().UTC(),
			SourceRefs: []string{o.ref}, ReadCount: 1, ExpectedCount: &expected, Complete: true,
			Tickets: []ticketintake.Ticket{{SourceRef: o.ref, Subject: o.subject, Profile: "tls-server", Requester: o.requester}}}); err != nil {
			t.Fatal(err)
		}
	}
	readApprovals := func() {
		t.Helper()
		for _, name := range []string{"items", "requests"} {
			sched, _, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", name)
			if err != nil {
				t.Fatal(err)
			}
			h.srv.dispatchTicketStatusJob(ctx, h.tenant, sched)
		}
		channel := &sshCollectionServedChannel{t: t, h: h}
		if count, err := relay.RunOnce(ctx, channel, stand.Client(), 2, 120); err != nil || count != 2 {
			for _, r := range channel.reports {
				t.Logf("report: %s %s", r.Outcome, r.Detail)
			}
			t.Fatalf("production relay = %d %v", count, err)
		}
	}
	request := func(ref string) (string, string, string) {
		t.Helper()
		r, found, err := h.store.IssuanceRequestByTicket(ctx, h.tenant, ref)
		if err != nil || !found {
			t.Fatalf("request for %s: %v %v", ref, found, err)
		}
		return r.Status, r.DecidedBy, r.DecisionReason
	}

	// Still requested in ServiceNow: nothing is decided.
	readApprovals()
	if s, _, _ := request("sc_req_item:ri0001"); s != "requested" {
		t.Fatalf("the requested item's request was decided early: %s", s)
	}
	sn.mu.Lock()
	sn.approvals["sc_req_item"]["ri0001"], sn.approvals["sc_request"]["rq0002"] = "approved", "rejected"
	sn.mu.Unlock()
	readApprovals()
	if s, by, reason := request("sc_req_item:ri0001"); s != "approved" || by != "servicenow:sc_req_item:RITM0010001" ||
		!strings.Contains(reason, "requested item RITM0010001 was approved in ServiceNow") {
		t.Fatalf("the approved requested item's request = %s %s %q", s, by, reason)
	}
	if s, by, reason := request("sc_request:rq0002"); s != "denied" || by != "servicenow:sc_request:REQ0010002" ||
		!strings.Contains(reason, "request REQ0010002 was rejected in ServiceNow") {
		t.Fatalf("the rejected request's request = %s %s %q", s, by, reason)
	}
	t.Logf("P13L2_CATALOG_APPROVALS_OK item=RITM0010001 request=REQ0010002")
}
