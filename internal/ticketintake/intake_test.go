// SPDX-License-Identifier: MPL-2.0

package ticketintake_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ticketintake"
)

func TestServiceNowEndpointAndReportParsingAreBounded(t *testing.T) {
	intent := ticketintake.SyncIntent{
		System:      ticketintake.SystemServiceNow,
		InstanceURL: "https://example.service-now.com/root",
		TokenRef:    "secret://itsm/token", SNTable: "sc_req_item", Query: "state=1",
		SubjectField: "u_subject", ProfileField: "u_profile",
		RequesterField: "opened_by", JustificationField: "short_description",
		PageLimit: 100,
	}
	endpoint, err := ticketintake.Endpoint(intent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(endpoint, "/api/now/table/sc_req_item?") ||
		!strings.Contains(endpoint, "sysparm_limit=100") ||
		!strings.Contains(endpoint, "sysparm_query=state%3D1") {
		t.Fatalf("bounded endpoint = %q", endpoint)
	}

	rows, err := ticketintake.Parse(strings.NewReader(`{"result":[
		{"sys_id":"tick-1","u_subject":"payments.example.test","u_profile":"tls-server",
		 "opened_by":{"display_value":"Dana Ops","value":"sys-user-1"},
		 "short_description":"rotate the listener"}
	]}`), intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SourceRef != "tick-1" || rows[0].Requester != "Dana Ops" {
		t.Fatalf("parsed tickets = %+v", rows)
	}
}

func TestServiceNowEndpointRejectsUnboundedTableAndLimit(t *testing.T) {
	for _, intent := range []ticketintake.SyncIntent{
		{System: ticketintake.SystemServiceNow, InstanceURL: "https://example.test", SNTable: "sys_user_password", PageLimit: 100},
		{System: ticketintake.SystemServiceNow, InstanceURL: "https://example.test", SNTable: "incident", PageLimit: 101},
	} {
		if _, err := ticketintake.Endpoint(intent); err == nil {
			t.Fatalf("Endpoint(%+v) accepted an unbounded ticket read", intent)
		}
	}
}

func TestServiceNowPageUsesStrictSysIDKeysetAUD47(t *testing.T) {
	intent := ticketintake.SyncIntent{
		System: ticketintake.SystemServiceNow, SweepID: "3d5c344d-f42e-48fc-a4d8-574f6717d047",
		InstanceURL: "https://example.service-now.com/root", TokenRef: "secret://itsm/token",
		SNTable: "sc_req_item", Query: "state=1", SubjectField: "u_subject", ProfileField: "u_profile",
		PageLimit: 2, Cursor: "tick-000100", ReadCount: 100,
	}
	endpoint, err := ticketintake.Endpoint(intent)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("sysparm_query"); got != "state=1^sys_id>tick-000100^ORDERBYsys_id" {
		t.Fatalf("stable ServiceNow query = %q", got)
	}

	page, err := ticketintake.ParsePage(strings.NewReader(`{"result":[
		{"sys_id":"tick-000101","u_subject":"one.example","u_profile":"tls-server"},
		{"sys_id":"tick-000102","u_subject":"two.example","u_profile":"tls-server"}
	]}`), intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Tickets) != 2 || strings.Join(page.SourceRefs, ",") != "tick-000101,tick-000102" || page.NextCursor != "tick-000102" {
		t.Fatalf("ServiceNow page = %+v", page)
	}
	if page.Complete {
		t.Fatal("a full ServiceNow page was incorrectly declared terminal")
	}
	if _, err := ticketintake.ParsePage(strings.NewReader(`{"result":[{"sys_id":"tick-000102"},{"sys_id":"tick-000101"}]}`), intent); err == nil {
		t.Fatal("descending ServiceNow sys_id page was accepted")
	}
	intent.PageLimit = 100
	page, err = ticketintake.ParsePage(strings.NewReader(`{"result":[{"sys_id":"tick-000101","u_subject":"one.example","u_profile":"tls-server"}]}`), intent)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Complete || page.NextCursor != "" {
		t.Fatalf("terminal ServiceNow page carries continuation authority: %+v", page)
	}
}

func TestJiraEnhancedSearchPageMapsFieldsAndTokenAUD47(t *testing.T) {
	intent := ticketintake.SyncIntent{
		System: ticketintake.SystemJira, SweepID: "7f29c364-c44a-484e-bcf2-f572ba1bf9d0",
		InstanceURL: "https://acme.atlassian.net", TokenRef: "secret://itsm/jira",
		JiraProject: "NHI", Query: `status = "Open"`,
		SubjectField: "customfield_10010", ProfileField: "customfield_10011",
		RequesterField: "reporter", JustificationField: "summary",
		PageLimit: 100, Cursor: "opaque-page-token", ReadCount: 100,
	}
	endpoint, err := ticketintake.Endpoint(intent)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Path != "/rest/api/3/search/jql" || query.Get("nextPageToken") != intent.Cursor ||
		query.Get("maxResults") != "100" || !strings.Contains(query.Get("jql"), `project = "NHI"`) ||
		!strings.HasSuffix(query.Get("jql"), " ORDER BY id ASC") {
		t.Fatalf("Jira endpoint = %q", endpoint)
	}

	page, err := ticketintake.ParsePage(strings.NewReader(`{
		"issues":[{"id":"10001","key":"NHI-101","fields":{
			"customfield_10010":"api.example.test","customfield_10011":"tls-server",
			"reporter":{"displayName":"Dana Ops"},"summary":"rotate listener"}}],
		"nextPageToken":"opaque-next","isLast":false,"total":201
	}`), intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Tickets) != 1 || page.Tickets[0].SourceRef != "10001" || page.Tickets[0].Requester != "Dana Ops" ||
		page.NextCursor != "opaque-next" || page.Complete || page.ExpectedCount == nil || *page.ExpectedCount != 201 {
		t.Fatalf("Jira page = %+v", page)
	}
	if _, err := ticketintake.Endpoint(ticketintake.SyncIntent{
		System: ticketintake.SystemJira, InstanceURL: "https://acme.atlassian.net", JiraProject: "NHI",
		Query: "status = Open ORDER BY created DESC", SubjectField: "a", ProfileField: "b", PageLimit: 100,
	}); err == nil {
		t.Fatal("operator-supplied Jira ORDER BY was accepted; it can defeat stable id ordering")
	}
}

func TestReportMustEchoExactSweepCursorAndProgressAUD47(t *testing.T) {
	expected := 101
	intent := ticketintake.SyncIntent{
		System: ticketintake.SystemJira, SweepID: "7f29c364-c44a-484e-bcf2-f572ba1bf9d0",
		InstanceURL: "https://acme.atlassian.net", TokenRef: "secret://itsm/jira", JiraProject: "NHI",
		SubjectField: "subject", ProfileField: "profile", PageLimit: 100,
		Cursor: "opaque-page-token", ReadCount: 100, ExpectedCount: &expected,
	}
	report := ticketintake.SyncReport{
		System: intent.System, SweepID: intent.SweepID, Cursor: intent.Cursor,
		ObservedAt: testTime(), SourceRefs: []string{"10001"},
		Tickets:   []ticketintake.Ticket{{SourceRef: "10001", Subject: "api.example", Profile: "tls-server"}},
		ReadCount: 101, ExpectedCount: &expected, Complete: true,
	}
	if err := ticketintake.ValidateReport(intent, report); err != nil {
		t.Fatalf("valid terminal report: %v", err)
	}
	report.Cursor = "different"
	if err := ticketintake.ValidateReport(intent, report); err == nil {
		t.Fatal("report signed for a different input cursor was accepted")
	}
}

func testTime() time.Time {
	return time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC)
}
