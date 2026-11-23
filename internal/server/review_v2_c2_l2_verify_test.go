// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

// R1 verifier V2, lead C2-L2 (who can arrange it). A tenant runs one "prod"
// ServiceNow intake source. A principal holding only certs:write (no
// certs:issue, no secrets:read) cannot decide the prod request through
// trstctl's approval route. It must not be able to decide it by adding a
// second source on the same table at an endpoint it controls. The decision's
// work note (P13-L1) must go back to the source that opened the request.
func TestReviewV2C2L2CertsWriteSourceDecidesAnotherSourcesRequest(t *testing.T) {
	const prodTokenValue = "servicenow-prod-intake-token" // #nosec G101 -- test-only fixture value, not a credential (CWE-798)
	prod := &p13ServiceNow{approvals: map[string]string{"a1b2c3": "requested"}, numbers: map[string]string{"a1b2c3": "CHG0030001"}}
	prodStand := httptest.NewTLSServer(prod.handler(t))
	t.Cleanup(prodStand.Close)
	// The endpoint the certs:write principal points its own source at: it
	// approves every sys_id it is asked about and remembers what it was sent.
	var (
		mu                 sync.Mutex
		asked              []string
		sentProdToken      bool
		endpointStatusGETs int
	)
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != "/api/now/table/change_request" {
			http.NotFound(w, r)
			return
		}
		endpointStatusGETs++
		sentProdToken = sentProdToken || r.Header.Get("Authorization") == "Bearer "+prodTokenValue
		ids := strings.Split(strings.TrimPrefix(r.URL.Query().Get("sysparm_query"), "sys_idIN"), ",")
		asked = append(asked, ids...)
		rows := []map[string]string{}
		for i, id := range ids {
			rows = append(rows, map[string]string{"sys_id": id, "number": fmt.Sprintf("CHG999%04d", i+1), "approval": "approved", "state": "-4"})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": rows})
	}))
	t.Cleanup(endpoint.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindTicketStatus}, withIsolatedTenant)
	ctx := t.Context()
	const tokenName = "v2-prod-intake-token" // #nosec G101 -- name of a test-only secret (CWE-798)
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, tokenName, []byte(prodTokenValue))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, tokenName, sealed)
	configure := func(token, name, url string) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", token, "v2-intake-"+name,
			map[string]any{"system": "servicenow", "name": name, "instance_url": url, "token_ref": "secret://" + tokenName,
				"sn_table": "change_request", "subject_field": "u_subject", "profile_field": "u_profile", "requester_field": "requested_by",
				"interval_seconds": 3600, "enabled": true})
	}
	admin := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "secrets:read")
	if status, out := configure(admin, "prod", prodStand.URL); status != http.StatusOK {
		t.Fatalf("configure prod intake: %d %s", status, out)
	}
	prodSched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", "prod")
	if err != nil || !found {
		t.Fatalf("prod schedule: %v %v", found, err)
	}
	intent := ticketSyncIntent(prodSched)
	expected := 1
	if _, err := h.srv.ingestTicketReport(ctx, h.tenant, "v2-prod-sync-1", intent, ticketintake.SyncReport{
		Schedule: "prod", System: "servicenow", SweepID: intent.SweepID, ObservedAt: time.Now().UTC(),
		SourceRefs: []string{"a1b2c3"}, ReadCount: 1, ExpectedCount: &expected, Complete: true,
		Tickets: []ticketintake.Ticket{{SourceRef: "a1b2c3", Subject: "payments.example.test", Profile: "tls-server", Requester: "dana@example.test"}},
	}); err != nil {
		t.Fatal(err)
	}
	request, found, err := h.store.IssuanceRequestByTicket(ctx, h.tenant, "change_request:a1b2c3")
	if err != nil || !found || request.Status != "requested" {
		t.Fatalf("prod request: %+v %v %v", request, found, err)
	}

	writer := seedScopedTokenSubject(t, h.store, h.tenant, "v2-certs-writer", "certs:write")
	// Control: trstctl's own approval route needs certs:issue.
	status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/issuance-requests/"+request.ID+"/approve", writer, uuid.NewString(), map[string]any{})
	t.Logf("control: certs:write-only principal approves the prod request through trstctl -> %d %s", status, raw)
	if status != http.StatusForbidden {
		t.Fatalf("control: a certs:write-only principal approved through the route: %d %s", status, raw)
	}
	// The same principal adds a source named "lab" on the same table at its endpoint.
	status, raw = configure(writer, "lab", endpoint.URL)
	t.Logf("certs:write-only principal adds source \"lab\" (change_request, naming secret://%s) at an endpoint it controls -> %d %s", tokenName, status, raw)
	if status != http.StatusOK {
		return // the property holds: it cannot add a deciding source
	}
	labSched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", "lab")
	if err != nil || !found {
		t.Fatalf("lab schedule: %v %v", found, err)
	}
	h.srv.dispatchTicketStatusJob(ctx, h.tenant, labSched)
	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, endpoint.Client(), 1, 120); err != nil || count != 1 {
		t.Fatalf("production relay = %d %v reports %+v", count, err, channel.reports)
	}
	after, _, err := h.store.IssuanceRequestByTicket(ctx, h.tenant, "change_request:a1b2c3")
	if err != nil {
		t.Fatal(err)
	}
	var note ticketintake.NoteIntent
	var notes int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'ticket.note'`, h.tenant).Scan(&notes); err != nil || notes == 0 {
			return err
		}
		var payload []byte
		if err := tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'ticket.note' ORDER BY id DESC LIMIT 1`, h.tenant).Scan(&payload); err != nil {
			return err
		}
		return json.Unmarshal(payload, &note)
	}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotAsked, gotToken, gets := append([]string(nil), asked...), sentProdToken, endpointStatusGETs
	mu.Unlock()
	noteTo := "nowhere"
	switch note.InstanceURL {
	case prodStand.URL:
		noteTo = "the prod instance"
	case endpoint.URL:
		noteTo = "the certs:write principal's endpoint"
	}
	t.Logf("endpoint status reads=%d asked for prod sys_ids %v; bearer it received was the prod intake token: %v", gets, gotAsked, gotToken)
	t.Logf("prod request after the endpoint's read: status=%s decided_by=%q reason=%q", after.Status, after.DecidedBy, after.DecisionReason)
	t.Logf("decision work notes queued=%d; latest to %s (schedule %q) for ticket %s", notes, noteTo, note.Schedule, note.SourceRef)
	if after.Status != "requested" {
		t.Errorf("a source added by a certs:write-only principal (no certs:issue) decided the prod source's request: status=%s decided_by=%q", after.Status, after.DecidedBy)
	}
	if note.InstanceURL != "" && note.InstanceURL != prodStand.URL {
		t.Errorf("the prod request's decision work note (request, subject, decider) was queued to %s, not the prod instance", noteTo)
	}
	if gotToken {
		t.Errorf("the relay presented the prod intake token to an endpoint chosen by a principal without secrets:read (C3 cross-note pattern, A235-L2 scope-only check)")
	}
}

// R1 verifier V2, lead C2-L2 (second effect). Two Jira sources on different
// Jira instances; each instance has its own SEC-42. Each ticket must open its
// own request.
func TestReviewV2C2L2JiraKeysCollideAcrossInstances(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "secrets:read")
	for _, source := range []struct{ name, url string }{{"jira-a", "https://jira-a.example.test"}, {"jira-b", "https://jira-b.example.test"}} {
		if status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok, "v2-"+source.name,
			map[string]any{"system": "jira", "name": source.name, "instance_url": source.url, "token_ref": servedIntakeTokenRef, "jira_project": "SEC",
				"subject_field": "u_subject", "profile_field": "u_profile", "interval_seconds": 3600, "enabled": true}); status != http.StatusOK {
			t.Fatalf("configure %s: %d %s", source.name, status, out)
		}
	}
	ingest := func(name, issueID, subject string) TicketIntakeResult {
		t.Helper()
		sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "jira", name)
		if err != nil || !found {
			t.Fatalf("%s schedule: %v %v", name, found, err)
		}
		intent := ticketSyncIntent(sched)
		expected := 1
		res, err := h.srv.ingestTicketReport(ctx, h.tenant, "v2-"+name+"-sync-"+uuid.NewString(), intent, ticketintake.SyncReport{
			Schedule: name, System: "jira", SweepID: intent.SweepID, ObservedAt: time.Now().UTC(),
			SourceRefs: []string{issueID}, ReadCount: 1, ExpectedCount: &expected, Complete: true,
			Tickets: []ticketintake.Ticket{{SourceRef: issueID, ExternalKey: "SEC-42", Subject: subject, Profile: "tls-server", Requester: "lee@example.test"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	a := ingest("jira-a", "10042", "a-only.example.test")
	b := ingest("jira-b", "20042", "b-only.example.test")
	t.Logf("jira-a SEC-42: opened=%d already=%d; jira-b SEC-42 (another instance's ticket): opened=%d already=%d", a.Opened, a.Already, b.Opened, b.Already)
	if a.Opened != 1 {
		t.Fatalf("jira-a did not open its request: %+v", a)
	}
	if b.Opened != 1 {
		t.Errorf("jira-b's own SEC-42 (instance %s) never opened a request: counted as already opened by jira-a's SEC-42 (ticket_ref keyed by system:key only)", "jira-b.example.test")
	}
}

// CR-002: even an administrator who may configure both sources cannot make
// one same-table source read, decide, or receive notes for the other's ticket.
func TestCR002ServiceNowStatusAndNotesStayWithOpeningSource(t *testing.T) {
	prod := &p13ServiceNow{approvals: map[string]string{"same-id": "requested"}, numbers: map[string]string{"same-id": "CHG1001"}}
	lab := &p13ServiceNow{approvals: map[string]string{"same-id": "approved"}, numbers: map[string]string{"same-id": "CHG2001"}}
	prodStand := httptest.NewTLSServer(prod.handler(t))
	labStand := httptest.NewTLSServer(lab.handler(t))
	t.Cleanup(prodStand.Close)
	t.Cleanup(labStand.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindTicketStatus}, withIsolatedTenant)
	ctx := t.Context()
	const tokenName = "cr002-intake-token" // #nosec G101 -- test-only secret name (CWE-798)
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, tokenName, []byte("cr002-test-value"))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, tokenName, sealed)
	admin := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "secrets:read")
	configure := func(name, endpoint string) store.TicketIntakeSchedule {
		t.Helper()
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", admin, uuid.NewString(),
			map[string]any{"system": "servicenow", "name": name, "instance_url": endpoint, "token_ref": "secret://" + tokenName,
				"sn_table": "change_request", "subject_field": "u_subject", "profile_field": "u_profile", "interval_seconds": 3600, "enabled": true}); status != http.StatusOK {
			t.Fatalf("configure %s: %d %s", name, status, body)
		}
		sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", name)
		if err != nil || !found {
			t.Fatalf("source %s: %v %v", name, found, err)
		}
		return sched
	}
	prodSched, labSched := configure("prod", prodStand.URL), configure("lab", labStand.URL)
	ingest := func(sched store.TicketIntakeSchedule, subject string) {
		t.Helper()
		intent := ticketSyncIntent(sched)
		expected := 1
		result, err := h.srv.ingestTicketReport(ctx, h.tenant, uuid.NewString(), intent, ticketintake.SyncReport{
			Schedule: sched.Name, System: "servicenow", SweepID: intent.SweepID, ObservedAt: time.Now().UTC(),
			SourceRefs: []string{"same-id"}, ReadCount: 1, ExpectedCount: &expected, Complete: true,
			Tickets: []ticketintake.Ticket{{SourceRef: "same-id", Subject: subject, Profile: "tls-server", Requester: "dana@example.test"}},
		})
		if err != nil || result.Opened != 1 {
			t.Fatalf("ingest %s: %+v %v", sched.Name, result, err)
		}
	}
	ingest(prodSched, "prod.example.test")
	h.srv.dispatchTicketStatusJob(ctx, h.tenant, labSched)
	if pending, err := h.store.HasPendingTicketStatusJob(ctx, h.tenant, labSched.Name); err != nil || pending {
		t.Fatalf("lab queued a read of prod's pending sys_id: pending=%v err=%v", pending, err)
	}
	ingest(labSched, "lab.example.test")
	prodSource, _ := ticketintake.SourceIdentity("servicenow", prodSched.Name, prodSched.InstanceURL)
	labSource, _ := ticketintake.SourceIdentity("servicenow", labSched.Name, labSched.InstanceURL)
	request := func(source string) store.IssuanceRequest {
		t.Helper()
		r, found, err := h.store.IssuanceRequestByTicketSource(ctx, h.tenant, source, "change_request:same-id")
		if err != nil || !found {
			t.Fatalf("source request %s: %v %v", source, found, err)
		}
		return r
	}
	if request(prodSource).ID == request(labSource).ID {
		t.Fatal("two source requests have one ID")
	}
	h.srv.dispatchTicketStatusJob(ctx, h.tenant, labSched)
	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, labStand.Client(), 1, 120); err != nil || count != 1 {
		t.Fatalf("lab status relay: %d %v", count, err)
	}
	if got := request(prodSource).Status; got != "requested" {
		t.Fatalf("lab decided prod: %s", got)
	}
	if got := request(labSource).Status; got != "approved" {
		t.Fatalf("lab request was not decided: %s", got)
	}
	// Each decision's note must use its original URL and token reference.
	if _, err := h.srv.orch.DecideIssuanceRequest(ctx, h.tenant, request(prodSource).ID, "denied", "reviewer@example.test", "prod refusal", ""); err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'ticket.note' ORDER BY id`, h.tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		seen := map[string]bool{}
		for rows.Next() {
			var raw []byte
			var note ticketintake.NoteIntent
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &note); err != nil {
				return err
			}
			seen[note.Schedule+"|"+note.InstanceURL] = true
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if !seen["prod|"+prodStand.URL] || !seen["lab|"+labStand.URL] || len(seen) != 2 {
			return fmt.Errorf("notes routed to wrong sources: %v", seen)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Repointing an existing schedule does not reuse old source identity or
	// mistake the prior ticket's closed request for the new instance's ticket.
	repointed := configure("prod", labStand.URL)
	ingest(repointed, "repointed.example.test")
	newSource, err := ticketintake.SourceIdentity("servicenow", repointed.Name, repointed.InstanceURL)
	if err != nil || newSource == prodSource || request(newSource).ID == request(prodSource).ID {
		t.Fatalf("URL change reused the old source: new=%q old=%q err=%v", newSource, prodSource, err)
	}
}
