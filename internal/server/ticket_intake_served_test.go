// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
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
	h.srv.dispatchTicketSyncJob(t.Context(), h.tenant, sched)
	sched, found, err = h.store.GetTicketIntakeSchedule(t.Context(), h.tenant, "servicenow")
	if err != nil || !found || sched.CurrentSweepID == "" {
		t.Fatalf("named sweep not projected: %+v found=%v err=%v", sched, found, err)
	}
	intent := ticketSyncIntent(sched)
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
	expected := 2
	report := ticketintake.SyncReport{
		System: intent.System, SweepID: intent.SweepID, Cursor: intent.Cursor,
		ObservedAt: time.Now().UTC(), SourceRefs: []string{"tick-1", "tick-2"},
		ReadCount: 2, ExpectedCount: &expected, Complete: true,
		Tickets: []ticketintake.Ticket{
			{SourceRef: "tick-1", Subject: "payments.example.test", Profile: "tls-server", Requester: "Dana Ops", Justification: "cert for payments"},
			{SourceRef: "tick-2", Profile: "tls-server", Justification: "no subject mapped"},
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

func TestServedTicketIntakePaginatesBothProvidersWithoutGapsAUD47(t *testing.T) {
	ctx := t.Context()
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	configs := []map[string]any{
		{
			"system": "servicenow", "instance_url": "https://servicenow.internal.example",
			"token_ref": servedIntakeTokenRef, "sn_table": "sc_req_item", "query": "state=1",
			"subject_field": "u_subject", "profile_field": "u_profile",
			"requester_field": "opened_by", "justification_field": "short_description",
			"interval_seconds": 3600, "enabled": true,
		},
		{
			"system": "jira", "instance_url": "https://acme.atlassian.net",
			"token_ref": servedIntakeTokenRef, "jira_project": "NHI", "query": "status = Open",
			"subject_field": "customfield_10001", "profile_field": "customfield_10002",
			"requester_field": "reporter", "justification_field": "description",
			"interval_seconds": 3600, "enabled": true,
		},
	}
	for i, body := range configs {
		status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok,
			fmt.Sprintf("aud47-config-%d", i), body)
		if status != http.StatusOK {
			t.Fatalf("configure %v: %d %s", body["system"], status, out)
		}
	}

	type providerRun struct {
		system        string
		firstPayload  []byte
		firstKey      string
		firstIntent   ticketintake.SyncIntent
		firstReport   ticketintake.SyncReport
		secondPayload []byte
		secondKey     string
		secondIntent  ticketintake.SyncIntent
	}
	runs := make([]providerRun, 0, 2)
	for _, system := range []string{ticketintake.SystemServiceNow, ticketintake.SystemJira} {
		sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, system)
		if err != nil || !found {
			t.Fatalf("load %s schedule: found=%v err=%v", system, found, err)
		}
		h.srv.dispatchTicketSyncJob(ctx, h.tenant, sched)
		payload, key, intent := latestTicketSyncCommandAUD47(t, h, system)
		if intent.Cursor != "" || intent.ReadCount != 0 || intent.SweepID == "" || intent.PageLimit != 100 {
			t.Fatalf("initial %s intent = %+v", system, intent)
		}
		expected := 101
		refs, tickets := ticketPageAUD47(system, 1, 100)
		nextCursor := refs[len(refs)-1]
		if system == ticketintake.SystemJira {
			nextCursor = "jira-page-after-100"
		}
		report := ticketintake.SyncReport{
			System: system, SweepID: intent.SweepID, Cursor: intent.Cursor,
			ObservedAt: time.Now().UTC(), SourceRefs: refs, Tickets: tickets,
			ReadCount: 100, ExpectedCount: &expected, Complete: false, NextCursor: nextCursor,
		}
		reportJSON := mustJSON(t, report)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- h.srv.recordTicketSync(ctx, h.tenant, "relay-aud47", key, payload, reportJSON)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent %s page-one receipt: %v", system, err)
			}
		}
		sched, found, err = h.store.GetTicketIntakeSchedule(ctx, h.tenant, system)
		if err != nil || !found || sched.ReadCount != 100 || sched.PagesCompleted != 1 || sched.CoverageComplete ||
			sched.LastRunAt != nil || sched.Cursor != nextCursor || sched.EligibleCount != 100 || sched.SkippedCount != 0 {
			t.Fatalf("%s after page one = %+v found=%v err=%v", system, sched, found, err)
		}
		secondPayload, secondKey, secondIntent := latestTicketSyncCommandAUD47(t, h, system)
		if secondIntent.SweepID != intent.SweepID || secondIntent.Cursor != nextCursor ||
			secondIntent.ReadCount != 100 || secondIntent.ExpectedCount == nil || *secondIntent.ExpectedCount != expected {
			t.Fatalf("%s continuation = %+v", system, secondIntent)
		}
		runs = append(runs, providerRun{
			system: system, firstPayload: payload, firstKey: key, firstIntent: intent, firstReport: report,
			secondPayload: secondPayload, secondKey: secondKey, secondIntent: secondIntent,
		})
	}

	// A failed Jira attempt records an honest error but retains the exact opaque
	// token. Recovery may enqueue the same command again, never page one.
	jira := runs[1]
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND destination = 'ticket.sync' AND idempotency_key = $2`,
			h.tenant, jira.secondKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if healed, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || healed != 1 {
		t.Fatalf("restart repair of Jira continuation: healed=%d err=%v", healed, err)
	}
	assertOneTicketCommandAUD47(t, h, jira.secondKey)
	failedAt := time.Now().UTC()
	if err := h.srv.recordTicketSyncFailure(ctx, h.tenant, jira.secondKey, jira.secondPayload, 1, failedAt,
		"provider request timed out"); err != nil {
		t.Fatalf("record Jira failure: %v", err)
	}
	jiraSchedule, _, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, ticketintake.SystemJira)
	if err != nil || jiraSchedule.Cursor != jira.secondIntent.Cursor || jiraSchedule.ReadCount != 100 ||
		jiraSchedule.CoverageComplete || !strings.Contains(jiraSchedule.LastError, "timed out") {
		t.Fatalf("Jira failure changed its checkpoint: %+v err=%v", jiraSchedule, err)
	}
	if err := h.srv.orch.ResumeTicketIntakeSweep(ctx, h.tenant, jira.secondIntent); err != nil {
		t.Fatalf("resume exact Jira cursor: %v", err)
	}
	assertOneTicketCommandAUD47(t, h, jira.secondKey)

	for _, run := range runs {
		expected := 101
		refs, tickets := ticketPageAUD47(run.system, 101, 101)
		report := ticketintake.SyncReport{
			System: run.system, SweepID: run.secondIntent.SweepID, Cursor: run.secondIntent.Cursor,
			ObservedAt: time.Now().UTC(), SourceRefs: refs, Tickets: tickets,
			ReadCount: 101, ExpectedCount: &expected, Complete: true,
		}
		if err := h.srv.recordTicketSync(ctx, h.tenant, "relay-aud47", run.secondKey,
			run.secondPayload, mustJSON(t, report)); err != nil {
			t.Fatalf("record %s terminal page: %v", run.system, err)
		}
		sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, run.system)
		if err != nil || !found || sched.ReadCount != 101 || sched.PagesCompleted != 2 || !sched.CoverageComplete ||
			sched.LastRunAt == nil || sched.Cursor != "" || sched.EligibleCount != 101 || sched.SkippedCount != 0 || sched.LastError != "" {
			t.Fatalf("%s terminal coverage = %+v found=%v err=%v", run.system, sched, found, err)
		}
	}

	requests, err := h.store.ListIssuanceRequests(ctx, h.tenant, "", 500)
	if err != nil || len(requests) != 202 {
		t.Fatalf("requests after two 101-ticket providers = %d err=%v", len(requests), err)
	}
	counts := map[string]int{}
	seenTickets := map[string]bool{}
	for _, request := range requests {
		counts[request.Origin]++
		if seenTickets[request.TicketRef] {
			t.Fatalf("duplicate request ticket_ref %q", request.TicketRef)
		}
		seenTickets[request.TicketRef] = true
	}
	if counts[ticketintake.SystemServiceNow] != 101 || counts[ticketintake.SystemJira] != 101 ||
		!seenTickets["sc_req_item:sn-001"] || !seenTickets["jira:NHI-101"] {
		t.Fatalf("provider request coverage = %+v", counts)
	}

	// Losing the result acknowledgment replays the same first-page event. Its
	// stable event and ticket identities must not roll the terminal checkpoint
	// backward or open a 203rd request.
	for _, run := range runs {
		if err := h.srv.recordTicketSync(ctx, h.tenant, "relay-aud47", run.firstKey,
			run.firstPayload, mustJSON(t, run.firstReport)); err != nil {
			t.Fatalf("replay %s page one: %v", run.system, err)
		}
	}
	requests, err = h.store.ListIssuanceRequests(ctx, h.tenant, "", 500)
	if err != nil || len(requests) != 202 {
		t.Fatalf("page replay changed request cardinality: %d err=%v", len(requests), err)
	}

	// Cold rebuild throws away the relational projection and derives it from
	// immutable events. Both terminal checkpoints and every request must return.
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold event rebuild: %v", err)
	}
	requests, err = h.store.ListIssuanceRequests(ctx, h.tenant, "", 500)
	if err != nil || len(requests) != 202 {
		t.Fatalf("cold rebuild requests = %d err=%v", len(requests), err)
	}
	for _, system := range []string{ticketintake.SystemServiceNow, ticketintake.SystemJira} {
		sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, system)
		if err != nil || !found || !sched.CoverageComplete || sched.ReadCount != 101 || sched.PagesCompleted != 2 {
			t.Fatalf("rebuilt %s checkpoint = %+v found=%v err=%v", system, sched, found, err)
		}
	}

	const otherTenant = "88888888-8888-4888-8888-888888888847"
	if _, err := h.store.SystemPool().Exec(ctx,
		`INSERT INTO tenants (tenant_id, name) VALUES ($1, 'aud47-other-tenant')`, otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, found, err := h.store.GetTicketIntakeSchedule(ctx, otherTenant, ticketintake.SystemJira); err != nil || found {
		t.Fatalf("other tenant read Jira checkpoint: found=%v err=%v", found, err)
	}
	if foreign, err := h.store.ListIssuanceRequests(ctx, otherTenant, "", 500); err != nil || len(foreign) != 0 {
		t.Fatalf("other tenant read %d requests: %v", len(foreign), err)
	}
}

func ticketPageAUD47(system string, first, last int) ([]string, []ticketintake.Ticket) {
	refs := make([]string, 0, last-first+1)
	tickets := make([]ticketintake.Ticket, 0, last-first+1)
	for i := first; i <= last; i++ {
		ref, key := fmt.Sprintf("sn-%03d", i), ""
		if system == ticketintake.SystemJira {
			ref, key = strconv.Itoa(i), fmt.Sprintf("NHI-%d", i)
		}
		refs = append(refs, ref)
		tickets = append(tickets, ticketintake.Ticket{
			SourceRef: ref, ExternalKey: key, Subject: fmt.Sprintf("%s-%03d.example.test", system, i),
			Profile: "tls-server", Requester: "Dana Ops", Justification: "AUD-47 bounded intake",
		})
	}
	return refs, tickets
}

func latestTicketSyncCommandAUD47(t *testing.T, h *servedHarness, system string) ([]byte, string, ticketintake.SyncIntent) {
	t.Helper()
	var payload []byte
	var key string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT payload, idempotency_key FROM outbox
			WHERE tenant_id = $1 AND destination = 'ticket.sync'
			  AND convert_from(payload, 'UTF8')::jsonb ->> 'system' = $2
			ORDER BY id DESC LIMIT 1`, h.tenant, system).Scan(&payload, &key)
	}); err != nil {
		t.Fatalf("load latest %s command: %v", system, err)
	}
	var intent ticketintake.SyncIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatalf("decode latest %s command: %v", system, err)
	}
	return payload, key, intent
}

func assertOneTicketCommandAUD47(t *testing.T, h *servedHarness, key string) {
	t.Helper()
	var count int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox
			WHERE tenant_id = $1 AND destination = 'ticket.sync' AND idempotency_key = $2`, h.tenant, key).Scan(&count)
	}); err != nil || count != 1 {
		t.Fatalf("ticket command %q count = %d err=%v", key, count, err)
	}
}
