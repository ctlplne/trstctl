// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/ticketintake"
)

func TestRelayTicketSyncRedeemsReadsParsesAndReports(t *testing.T) {
	var method, authorization string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, authorization = r.Method, r.Header.Get("Authorization")
		w.Header().Set("X-Total-Count", "1")
		_, _ = w.Write([]byte(`{"result":[{"sys_id":"tick-1","u_subject":"api.example.test","u_profile":"tls-server"}]}`))
	}))
	defer sink.Close()
	intent := ticketintake.SyncIntent{
		System: ticketintake.SystemServiceNow, SweepID: "4cc0fe9c-bf70-4c22-bd92-fbc00f13225a",
		InstanceURL: sink.URL, TokenRef: "secret://itsm/token", SNTable: "incident",
		SubjectField: "u_subject", ProfileField: "u_profile", PageLimit: 100,
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	ch := &fakeChannel{
		jobs:     []relay.Job{{JobID: 31, Kind: relay.KindTicketSync, Attempt: 1, Payload: payload}},
		material: map[string][]byte{"secret://itsm/token": []byte("jit-token")},
	}
	if executed, err := relay.RunOnce(t.Context(), ch, sink.Client(), 1, 30); err != nil || executed != 1 {
		t.Fatalf("executed=%d err=%v reports=%+v", executed, err, ch.reports)
	}
	if method != http.MethodGet || authorization != "Bearer jit-token" || ch.redeemed != 1 {
		t.Fatalf("method=%q authorization=%q redemptions=%d", method, authorization, ch.redeemed)
	}
	var report ticketintake.SyncReport
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Tickets) != 1 || report.Tickets[0].Subject != "api.example.test" ||
		report.SweepID != intent.SweepID || report.ReadCount != 1 || !report.Complete ||
		report.ExpectedCount == nil || *report.ExpectedCount != 1 || report.NextCursor != "" {
		t.Fatalf("report = %+v", report)
	}
}

func TestRelayTicketSyncUsesJiraOpaqueContinuationAUD47(t *testing.T) {
	var gotPath, authorization string
	var gotQuery url.Values
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, authorization = r.URL.Path, r.URL.Query(), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{
			"issues":[{"id":"101","key":"NHI-101","fields":{
				"customfield_10001":"api.example.test","customfield_10002":"tls-server",
				"reporter":{"displayName":"Dana Ops"}}}],
			"nextPageToken":"opaque-after-101","isLast":false,"total":201}`))
	}))
	defer sink.Close()
	intent := ticketintake.SyncIntent{
		System: ticketintake.SystemJira, SweepID: "4cc0fe9c-bf70-4c22-bd92-fbc00f13225b",
		InstanceURL: sink.URL, TokenRef: "secret://itsm/jira", JiraProject: "NHI", Query: "status = Open",
		SubjectField: "customfield_10001", ProfileField: "customfield_10002", RequesterField: "reporter",
		PageLimit: 100, Cursor: "opaque-before-101", ReadCount: 100,
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	ch := &fakeChannel{
		jobs:     []relay.Job{{JobID: 32, Kind: relay.KindTicketSync, Attempt: 1, Payload: payload}},
		material: map[string][]byte{"secret://itsm/jira": []byte("jit-jira-token")},
	}
	if executed, err := relay.RunOnce(t.Context(), ch, sink.Client(), 1, 30); err != nil || executed != 1 {
		t.Fatalf("executed=%d err=%v reports=%+v", executed, err, ch.reports)
	}
	if gotPath != "/rest/api/3/search/jql" || authorization != "Bearer jit-jira-token" ||
		gotQuery.Get("nextPageToken") != intent.Cursor || gotQuery.Get("maxResults") != "100" ||
		gotQuery.Get("jql") != `project = "NHI" AND (status = Open) ORDER BY id ASC` {
		t.Fatalf("Jira request path=%q query=%v authorization=%q", gotPath, gotQuery, authorization)
	}
	var report ticketintake.SyncReport
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
		t.Fatal(err)
	}
	if report.System != ticketintake.SystemJira || report.SweepID != intent.SweepID || report.Cursor != intent.Cursor ||
		len(report.Tickets) != 1 || report.Tickets[0].SourceRef != "101" || report.Tickets[0].ExternalKey != "NHI-101" ||
		report.ReadCount != 101 || report.ExpectedCount == nil || *report.ExpectedCount != 201 || report.Complete ||
		report.NextCursor != "opaque-after-101" {
		t.Fatalf("Jira report = %+v", report)
	}
}
