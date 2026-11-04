// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

// p13ServiceNow is a ServiceNow stand-in: change requests with an approval,
// and incidents created, found by correlation and resolved over the Table API.
type p13ServiceNow struct {
	mu        sync.Mutex
	approvals map[string]string // change sys_id -> approval
	numbers   map[string]string // change sys_id -> number
	incidents []map[string]string
	patches   int
	statusGET int
}

func (s *p13ServiceNow) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/change_request":
			s.statusGET++
			query := r.URL.Query().Get("sysparm_query")
			ids := strings.Split(strings.TrimPrefix(query, "sys_idIN"), ",")
			rows := []map[string]string{}
			for _, id := range ids {
				if approval, ok := s.approvals[id]; ok {
					rows = append(rows, map[string]string{"sys_id": id, "number": s.numbers[id], "approval": approval, "state": "-4"})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": rows})
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/table/incident":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			record := map[string]string{"sys_id": "inc" + strconv.Itoa(len(s.incidents)+1), "state": "1",
				"correlation_id": body["correlation_id"], "close_notes": ""}
			s.incidents = append(s.incidents, record)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"result": record})
		case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/incident":
			want := strings.TrimPrefix(r.URL.Query().Get("sysparm_query"), "correlation_id=")
			rows := []map[string]string{}
			for _, record := range s.incidents {
				if record["correlation_id"] == want {
					rows = append(rows, map[string]string{"sys_id": record["sys_id"], "state": record["state"], "close_notes": record["close_notes"]})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": rows})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/now/table/incident/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/now/table/incident/")
			var body map[string]string
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			for _, record := range s.incidents {
				if record["sys_id"] == id {
					s.patches++
					record["state"], record["close_notes"] = body["state"], body["close_notes"]
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"sys_id": id}})
		default:
			t.Errorf("unexpected ServiceNow call: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	})
}

// P13 Done-when 1: approving a change request in ServiceNow approves the
// matching trstctl request once. The approval is read through the production
// relay with the intake schedule's token; a rejection denies; reading the same
// approvals again records nothing new.
func TestServedServiceNowChangeApprovalDecidesTheRequestOnceP13(t *testing.T) {
	sn := &p13ServiceNow{approvals: map[string]string{"a1b2c3": "requested", "d4e5f6": "requested"},
		numbers: map[string]string{"a1b2c3": "CHG0030001", "d4e5f6": "CHG0030002"}}
	stand := httptest.NewTLSServer(sn.handler(t))
	t.Cleanup(stand.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindTicketStatus})
	ctx := t.Context()
	const tokenName = "p13-intake-token" // #nosec G101 -- the name of a test-only secret, not a credential (CWE-798)
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, tokenName, []byte("servicenow-intake-token"))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, tokenName, sealed)
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	if status, out := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok, "p13-intake",
		map[string]any{"system": "servicenow", "name": "changes", "instance_url": stand.URL, "token_ref": "secret://" + tokenName,
			"sn_table": "change_request", "subject_field": "u_subject", "profile_field": "u_profile", "requester_field": "requested_by",
			"interval_seconds": 3600, "enabled": true}); status != http.StatusOK {
		t.Fatalf("configure intake: %d %s", status, out)
	}
	sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", "changes")
	if err != nil || !found {
		t.Fatalf("schedule: %v %v", found, err)
	}
	// Intake opened one request per change, as the sync pass does.
	intent := ticketSyncIntent(sched)
	expected := 2
	if _, err := h.srv.ingestTicketReport(ctx, h.tenant, "p13-sync-1", intent, ticketintake.SyncReport{
		Schedule: "changes", System: "servicenow", SweepID: intent.SweepID, ObservedAt: time.Now().UTC(),
		SourceRefs: []string{"a1b2c3", "d4e5f6"}, ReadCount: 2, ExpectedCount: &expected, Complete: true,
		Tickets: []ticketintake.Ticket{
			{SourceRef: "a1b2c3", Subject: "payments.example.test", Profile: "tls-server", Requester: "dana@example.test"},
			{SourceRef: "d4e5f6", Subject: "legacy.example.test", Profile: "tls-server", Requester: "lee@example.test"},
		}}); err != nil {
		t.Fatal(err)
	}
	request := func(ref string) store.IssuanceRequest {
		t.Helper()
		r, found, err := h.store.IssuanceRequestByTicket(ctx, h.tenant, "change_request:"+ref)
		if err != nil || !found {
			t.Fatalf("request for %s: %v %v", ref, found, err)
		}
		return r
	}
	readApprovals := func() *sshCollectionServedChannel {
		t.Helper()
		h.srv.dispatchTicketStatusJob(ctx, h.tenant, sched)
		channel := &sshCollectionServedChannel{t: t, h: h}
		if count, err := relay.RunOnce(ctx, channel, stand.Client(), 1, 120); err != nil || count != 1 {
			t.Fatalf("production relay = %d %v reports %+v", count, err, channel.reports)
		}
		return channel
	}

	// Still waiting in ServiceNow: nothing is decided.
	readApprovals()
	if a, b := request("a1b2c3"), request("d4e5f6"); a.Status != "requested" || b.Status != "requested" {
		t.Fatalf("decided before ServiceNow did: %s %s", a.Status, b.Status)
	}
	sn.mu.Lock()
	sn.approvals["a1b2c3"], sn.approvals["d4e5f6"] = "approved", "rejected"
	sn.mu.Unlock()
	channel := readApprovals()
	approved, denied := request("a1b2c3"), request("d4e5f6")
	if approved.Status != "approved" || approved.DecidedBy != "servicenow:change_request:CHG0030001" ||
		!strings.Contains(approved.DecisionReason, "CHG0030001 was approved in ServiceNow") {
		t.Fatalf("approved change = %+v", approved)
	}
	if denied.Status != "denied" || denied.DecidedBy != "servicenow:change_request:CHG0030002" {
		t.Fatalf("rejected change = %+v", denied)
	}
	// Nothing waits any more, so no read is queued; and the same report again
	// records nothing new.
	before := sn.statusGET
	h.srv.dispatchTicketStatusJob(ctx, h.tenant, sched)
	if pending, err := h.store.HasPendingTicketStatusJob(ctx, h.tenant, "changes"); err != nil || pending || sn.statusGET != before {
		t.Fatalf("a read was queued with nothing waiting: %v %v", pending, err)
	}
	report := channel.reports[len(channel.reports)-1]
	var payload []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'ticket.status' ORDER BY id DESC LIMIT 1`, h.tenant).Scan(&payload)
	}); err != nil {
		t.Fatal(err)
	}
	svc := &agentService{store: h.store, orch: h.srv.orch}
	if err := svc.recordTicketStatus(ctx, h.tenant, payload, report.Detail); err != nil {
		t.Fatalf("replayed report: %v", err)
	}
	if again := request("a1b2c3"); again.Status != "approved" || again.DecidedAt == nil || approved.DecidedAt == nil || !again.DecidedAt.Equal(*approved.DecidedAt) {
		t.Fatalf("the replay changed the decision: %+v", again)
	}
	if recorded, err := h.srv.orch.DecideIssuanceRequestFromTicket(ctx, h.tenant, approved.ID, "approved",
		"servicenow:change_request:CHG0030001", "again"); err != nil || recorded {
		t.Fatalf("deciding the approved change again recorded=%v err=%v", recorded, err)
	}
	if _, found, err := h.log.EventByID(ctx, orchestrator.TicketDecisionEventID(h.tenant, approved.ID)); err != nil || !found {
		t.Fatalf("the change's one decision event: found=%v err=%v", found, err)
	}
}

// P13 Done-when 2: closing a trstctl incident updates the ServiceNow ticket its
// response dispatch opened, and a replayed update changes nothing.
func TestServedClosingAnIncidentResolvesItsServiceNowTicketOnceP13(t *testing.T) {
	sn := &p13ServiceNow{}
	stand := httptest.NewServer(sn.handler(t))
	t.Cleanup(stand.Close)
	t.Setenv("TRSTCTL_P13_SERVICENOW_TOKEN", "servicenow-test-token")
	binding := api.ServiceNowBinding{InstanceURL: stand.URL, TokenRef: "env:TRSTCTL_P13_SERVICENOW_TOKEN", // #nosec G101 -- an env: reference to a test-only value (CWE-798)
		AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{serviceNowSinkCIDR(t, stand.URL)}}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.ServiceNowBindings = []api.ServiceNowBinding{binding} })
	ctx := t.Context()
	incident, err := h.srv.orch.RecordIncidentExecution(ctx, h.tenant, store.IncidentExecution{
		ID: "77777777-7777-4777-8777-777777777777", CompromisedIdentityID: "88888888-8888-4888-8888-888888888888",
		Status: "executed", Phase: "legacy_evidence_only", Reason: "P13 incident", BlastRadius: json.RawMessage(`{"node":{"id":"p13"}}`),
		RevocationStatus: "recorded", EvidenceBundleFormat: "jws", EvidenceBundle: "p13.header.signature",
		FailedTargets: []string{}, RollbackRefs: []string{}, IdempotencyKey: "p13-incident", CreatedBy: "p13-commander",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "incidents:write", "incidents:read", string(authz.PrivateEgress))
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/incidents/response-integrations/dispatch", tok, "p13-dispatch", map[string]any{
		"incident_id": incident.ID, "title": "Contain the payments key", "severity": "critical",
		"destinations": []map[string]any{{"id": "servicenow-ir", "provider": "servicenow", "instance_url": stand.URL, "table": "incident",
			"token_ref": "env:TRSTCTL_P13_SERVICENOW_TOKEN", "allow_private_endpoint": true, "private_egress_cidrs": binding.PrivateEgressCIDRs}}, // #nosec G101 -- an env: reference to a test-only value (CWE-798)
	}); status != http.StatusAccepted {
		t.Fatalf("dispatch = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	sn.mu.Lock()
	if len(sn.incidents) != 1 || sn.incidents[0]["correlation_id"] != orchestrator.IncidentCorrelationID(incident.ID) {
		t.Fatalf("ServiceNow incidents = %+v", sn.incidents)
	}
	sn.mu.Unlock()

	closeBody := map[string]any{"resolution": "replacement deployed and old key revoked",
		"servicenow": map[string]any{"instance_url": stand.URL, "token_ref": "env:TRSTCTL_P13_SERVICENOW_TOKEN", "allow_private_endpoint": true}} // #nosec G101 -- an env: reference to a test-only value (CWE-798)
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/incidents/executions/"+incident.ID+"/close", tok, "p13-close", closeBody)
	if status != http.StatusOK || !strings.Contains(string(body), `"servicenow":"queued"`) {
		t.Fatalf("close = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	sn.mu.Lock()
	ticket := sn.incidents[0]
	if sn.patches != 1 || ticket["state"] != "6" || !strings.Contains(ticket["close_notes"], "replacement deployed") {
		t.Fatalf("ServiceNow after the close = %+v after %d patches", ticket, sn.patches)
	}
	sn.mu.Unlock()
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/incidents/executions/"+incident.ID+"/closure", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"servicenow":"resolved"`) {
		t.Fatalf("closure = %d %s", status, body)
	}

	// A replayed delivery finds the ticket already resolved with these notes.
	var row struct {
		id      int64
		payload []byte
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, payload FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, orchestrator.DestinationITSMServiceNowClose).Scan(&row.id, &row.payload)
	}); err != nil {
		t.Fatal(err)
	}
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	if err := dispatcher.Deliver(ctx, orchestrator.Message{ID: row.id, TenantID: h.tenant, Destination: orchestrator.DestinationITSMServiceNowClose,
		Payload: row.payload, IdempotencyKey: orchestrator.ServiceNowCloseKey(incident.ID)}); err != nil {
		t.Fatalf("replayed delivery: %v", err)
	}
	// Closing it again the same way changes nothing; differently is refused.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/incidents/executions/"+incident.ID+"/close", tok, "p13-close-again", closeBody); status != http.StatusOK {
		t.Fatalf("the same close again = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/incidents/executions/"+incident.ID+"/close", tok, "p13-close-other",
		map[string]any{"resolution": "something else"}); status != http.StatusConflict {
		t.Fatalf("a different close = %d", status)
	}
	sn.mu.Lock()
	defer sn.mu.Unlock()
	if sn.patches != 1 {
		t.Fatalf("ServiceNow was patched %d times; the replays must change nothing", sn.patches)
	}
}
