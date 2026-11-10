// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

// A225-L1: a ticket's requester is recorded as the ticket system names them
// (Jira's email for the reporter, a ServiceNow display value), while an
// approver signs in under a login subject. The separation-of-duties check
// compared those two strings exactly, so the person who filed the ticket
// approved their own request under their login. One person, two identifiers:
// a member whose sign-in subject is an opaque provider id, whose member record
// holds the email and display name the tickets name. Neither of their ticket
// requests can be decided by them; another member decides both.
func TestServedTicketRequesterCannotApproveUnderTheirLoginA225L1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	const aliceSubject = "oidc|a225l1-alice-7f3c"
	if _, err := h.srv.orch.UpsertTenantMember(ctx, h.tenant, store.TenantMember{
		Subject: aliceSubject, Email: "Alice.Ng@corp.example", DisplayName: "Alice Ng", Roles: []string{"operator"}, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.UpsertTenantMember(ctx, h.tenant, store.TenantMember{
		Subject: "oidc|a225l1-bob-91aa", Email: "bob@corp.example", DisplayName: "Bob Ruiz", Roles: []string{"operator"}, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	alice := seedScopedTokenSubject(t, h.store, h.tenant, aliceSubject, "certs:issue", "certs:read")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "oidc|a225l1-bob-91aa", "certs:issue", "certs:read")
	admin := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", admin, "a225l1-intake", map[string]any{
		"system": "jira", "instance_url": "https://acme.atlassian.net", "token_ref": servedIntakeTokenRef,
		"jira_project": "NHI", "query": `status = "Open"`,
		"subject_field": "customfield_10010", "profile_field": "customfield_10011",
		"requester_field": "reporter", "justification_field": "summary",
		"interval_seconds": 3600, "enabled": true,
	})
	if status != http.StatusOK {
		t.Fatalf("configure intake: %d %s", status, out)
	}
	sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "jira")
	if err != nil || !found {
		t.Fatalf("schedule not persisted: %v %v", found, err)
	}
	h.srv.dispatchTicketSyncJob(ctx, h.tenant, sched)
	if sched, _, err = h.store.GetTicketIntakeSchedule(ctx, h.tenant, "jira"); err != nil || sched.CurrentSweepID == "" {
		t.Fatalf("sweep not started: %+v %v", sched, err)
	}
	intent := ticketSyncIntent(sched)
	// What the relay reads from Jira: the reporter as Jira returns a user,
	// with the email Jira shares, and a ticket whose reporter shows only a
	// display name.
	page, err := ticketintake.ParsePage(strings.NewReader(`{"issues":[
		{"id":"20001","key":"NHI-201","fields":{"customfield_10010":"pay-a.example.test","customfield_10011":"tls-server",
			"reporter":{"accountId":"5b10ac8d82e05b22cc7d4ef5","displayName":"Alice Ng","emailAddress":"alice.ng@corp.example"},"summary":"payments leaf"}},
		{"id":"20002","key":"NHI-202","fields":{"customfield_10010":"pay-b.example.test","customfield_10011":"tls-server",
			"reporter":{"accountId":"5b10ac8d82e05b22cc7d4ef5","displayName":"alice ng"},"summary":"payments leaf b"}}],
		"isLast":true,"total":2}`), intent)
	if err != nil {
		t.Fatal(err)
	}
	two := 2
	report := ticketintake.SyncReport{System: intent.System, SweepID: intent.SweepID, Cursor: intent.Cursor,
		ObservedAt: time.Now().UTC(), SourceRefs: page.SourceRefs, ReadCount: 2, ExpectedCount: &two, Complete: true, Tickets: page.Tickets}
	if res, err := h.srv.ingestTicketReport(ctx, h.tenant, "a225l1-sync", intent, report); err != nil || res.Opened != 2 {
		t.Fatalf("intake = %+v %v, want two requests", res, err)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/issuance-requests", admin, nil)
	var list struct {
		Items []struct {
			ID        string `json:"id"`
			Subject   string `json:"subject"`
			Requester string `json:"requester"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 2 {
		t.Fatalf("list requests: %d %s", status, body)
	}
	for _, request := range list.Items {
		want := map[string]string{"pay-a.example.test": "alice.ng@corp.example", "pay-b.example.test": "alice ng"}[request.Subject]
		if request.Requester != want {
			t.Fatalf("request for %s records requester %q, want %q (the reporter's email when Jira shares it)", request.Subject, request.Requester, want)
		}
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests/"+request.ID+"/approve", alice, "a225l1-alice-"+request.ID, nil)
		if status != http.StatusForbidden || !strings.Contains(string(body), "under another identifier") {
			t.Fatalf("the reporter approved their own %s request under their login: %d %s", request.Subject, status, body)
		}
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests/"+request.ID+"/approve", bob, "a225l1-bob-"+request.ID, nil)
		if status != http.StatusOK {
			t.Fatalf("another member could not approve the %s request: %d %s", request.Subject, status, body)
		}
	}
}
