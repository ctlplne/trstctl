// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/ownership"
)

// The relay half of I2: read the one permitted table from inside the segment,
// parse there, report records — never the raw response, never a decision.

func cmdbJob(t *testing.T, intent ownership.CMDBSyncIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 11, Kind: relay.KindCMDBSync, Attempt: 1, Payload: payload}
}

func TestRelayCMDBSyncReadsParsesAndReportsRecords(t *testing.T) {
	var seenPath, seenAuth, seenMethod, seenQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath, seenAuth, seenMethod, seenQuery = r.URL.Path, r.Header.Get("Authorization"), r.Method, r.URL.Query().Get("sysparm_query")
		w.Header().Set("X-Total-Count", "1")
		_, _ = w.Write([]byte(`{"result":[
			{"sys_id":"ci-9","name":"api","owned_by":{"display_value":"payments"},
			 "u_application":{"display_value":"APP-9"}}
		]}`))
	}))
	defer srv.Close()

	ch := &fakeChannel{
		jobs: []relay.Job{cmdbJob(t, ownership.CMDBSyncIntent{
			InstanceURL: srv.URL, TokenRef: "secret://itsm/token", PageLimit: 100,
			SweepID: "11111111-1111-4111-8111-111111111111", AfterSysID: "ci-8", ReadCount: 500,
		})},
		material: map[string][]byte{"secret://itsm/token": []byte("relay-redeemed-token")},
	}
	executed, err := relay.RunOnce(t.Context(), ch, srv.Client(), 4, 30)
	if err != nil || executed != 1 {
		t.Fatalf("executed = %d, %v; reports: %+v", executed, err, ch.reports)
	}
	if seenMethod != http.MethodGet {
		t.Fatalf("method = %q; a relay CMDB sync may only ever GET", seenMethod)
	}
	if !strings.HasSuffix(seenPath, "/api/now/table/cmdb_ci") {
		t.Fatalf("path = %q, want the fixed cmdb_ci table — the endpoint builder is shared with "+
			"the control plane precisely so this cannot drift onto another table", seenPath)
	}
	if seenAuth != "Bearer relay-redeemed-token" {
		t.Fatalf("Authorization = %q; the token must come from THIS attempt's redemption, not the payload", seenAuth)
	}
	if seenQuery != "sys_id>ci-8^ORDERBYsys_id" {
		t.Fatalf("query = %q, want the exact durable keyset continuation", seenQuery)
	}
	if ch.redeemed != 1 {
		t.Fatalf("redeemed %d times, want exactly 1", ch.redeemed)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v", ch.reports)
	}
	var report struct {
		SweepID       string             `json:"sweep_id"`
		AfterSysID    string             `json:"after_sys_id"`
		SourceRefs    []string           `json:"source_refs"`
		Records       []ownership.Record `json:"records"`
		ReadCount     int                `json:"read_count"`
		ExpectedCount *int               `json:"expected_count"`
		Complete      bool               `json:"complete"`
	}
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
		t.Fatalf("report detail is not a records document: %v", err)
	}
	if len(report.Records) != 1 || report.Records[0].OwnerName != "payments" {
		t.Fatalf("records = %+v; the relay parses and ships structure, not raw bytes", report.Records)
	}
	if report.SweepID != "11111111-1111-4111-8111-111111111111" || report.AfterSysID != "ci-8" {
		t.Fatalf("report continuation = sweep %q after %q; it must bind to the durable job page", report.SweepID, report.AfterSysID)
	}
	if len(report.SourceRefs) != 1 || report.SourceRefs[0] != "ci-9" || report.ReadCount != 501 {
		t.Fatalf("report coverage = refs %v read %d, want the complete observed page and cumulative 501", report.SourceRefs, report.ReadCount)
	}
	if report.ExpectedCount == nil || *report.ExpectedCount != 501 {
		t.Fatalf("expected_count = %v, want read-before 500 + the CMDB's one remaining row", report.ExpectedCount)
	}
	if !report.Complete {
		t.Fatal("one row under a 100-row bound did not report terminal completion")
	}
}

// A full page is never called terminal, even when the denominator happens to
// equal the cumulative read. The CMDB can add the next sys_id between the
// response and report; one short/empty page is the only bounded terminal proof.
func TestRelayCMDBSyncFullPageCarriesContinuationInsteadOfSuccessAUD46(t *testing.T) {
	var seen url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Query()
		w.Header().Set("X-Total-Count", "2")
		_, _ = w.Write([]byte(`{"result":[
			{"sys_id":"ci-0501","owned_by":"payments"},
			{"sys_id":"ci-0502","owned_by":"platform"}
		]}`))
	}))
	defer srv.Close()

	ch := &fakeChannel{
		jobs: []relay.Job{cmdbJob(t, ownership.CMDBSyncIntent{
			InstanceURL: srv.URL, TokenRef: "secret://itsm/token", PageLimit: 2,
			SweepID: "22222222-2222-4222-8222-222222222222", AfterSysID: "ci-0500", ReadCount: 500,
		})},
		material: map[string][]byte{"secret://itsm/token": []byte("t")},
	}
	if _, err := relay.RunOnce(t.Context(), ch, srv.Client(), 4, 30); err != nil {
		t.Fatal(err)
	}
	if seen.Get("sysparm_offset") != "" || seen.Get("sysparm_query") != "sys_id>ci-0500^ORDERBYsys_id" {
		t.Fatalf("request query = %v; continuation must be stable keyset pagination", seen)
	}
	var report struct {
		SourceRefs []string `json:"source_refs"`
		ReadCount  int      `json:"read_count"`
		Complete   bool     `json:"complete"`
	}
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
		t.Fatal(err)
	}
	if report.Complete || report.ReadCount != 502 || len(report.SourceRefs) != 2 || report.SourceRefs[1] != "ci-0502" {
		t.Fatalf("report = %+v, want an incomplete full page ending at ci-0502", report)
	}
}

func TestRelayCMDBSyncFailurePathsReportClosedPhrases(t *testing.T) {
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer deny.Close()

	cases := []struct {
		name string
		job  relay.Job
		ch   *fakeChannel
		want string
	}{
		{
			name: "garbage payload",
			job:  relay.Job{JobID: 1, Kind: relay.KindCMDBSync, Attempt: 1, Payload: []byte("{")},
			ch:   &fakeChannel{},
			want: "not a cmdb sync intent",
		},
		{
			name: "redemption missing the token ref",
			job:  cmdbJob(t, ownership.CMDBSyncIntent{InstanceURL: deny.URL, TokenRef: "secret://itsm/token"}),
			ch:   &fakeChannel{material: map[string][]byte{"secret://other": []byte("x")}},
			want: "did not include the cmdb token",
		},
		{
			name: "instance refuses",
			job:  cmdbJob(t, ownership.CMDBSyncIntent{InstanceURL: deny.URL, TokenRef: "secret://itsm/token"}),
			ch:   &fakeChannel{material: map[string][]byte{"secret://itsm/token": []byte("t")}},
			want: "status 403",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.ch.jobs = []relay.Job{tc.job}
			if _, err := relay.RunOnce(t.Context(), tc.ch, deny.Client(), 4, 30); err != nil {
				t.Fatal(err)
			}
			if len(tc.ch.reports) != 1 || tc.ch.reports[0].outcome != relay.OutcomeFailed {
				t.Fatalf("reports = %+v, want one failed", tc.ch.reports)
			}
			if !strings.Contains(tc.ch.reports[0].detail, tc.want) {
				t.Fatalf("detail %q does not carry %q; the closed phrase is what the operator acts on",
					tc.ch.reports[0].detail, tc.want)
			}
		})
	}
}
