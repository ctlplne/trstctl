// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// LS-1: a tenant's report schedules have distinct names. A second schedule
// under a name another holds, from the API or a tenant baseline, is refused
// before anything is appended. It used to append the schedule event and fail
// its projection on the (tenant, name) index: a 500, and an event no rebuild
// could apply. A log that already holds such an event rebuilds, the schedule
// it named never existing, as live.
func TestServedReportScheduleDuplicateNameIsAConflictLS1(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditArchiveDir = archiveRoot
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(&reportWorkerSigner{key: key}))
	})
	admin := seedScopedToken(t, h.store, h.tenant, "audit:write", "audit:read")
	const name = "monthly SOC 2 pack"
	definition := map[string]any{"framework": "soc2", "name": name, "report_type": "audit_summary", "interval_seconds": 3600}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/compliance/report-schedules", admin, "ls1-first", definition)
	if status != http.StatusCreated {
		t.Fatalf("first schedule: %d %s", status, body)
	}
	var first struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &first); err != nil || first.ID == "" {
		t.Fatalf("decode the first schedule: %v %s", err, body)
	}
	head := func() uint64 {
		t.Helper()
		seq, err := h.log.LastSequence(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return seq
	}
	before := head()
	definition["name"] = " " + name + " "
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/compliance/report-schedules", admin, "ls1-second", definition)
	var problem struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Code   string `json:"code"`
	}
	if status != http.StatusConflict || json.Unmarshal(body, &problem) != nil || problem.Code != "name_held" ||
		!strings.Contains(problem.Detail, `another report schedule is named "`+name+`"`) {
		t.Fatalf("a second schedule with the first's name = %d %s, want a 409 naming it", status, body)
	}

	// A tenant baseline's schedule under the same name fails its step.
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "provider:ops@provider.example"})
	applied, err := h.srv.api.ApplyTenantBaseline(ctx, h.tenant, "ls1", api.TenantBaseline{ReportSchedules: []api.BaselineReportSchedule{{
		Key: "weekly", Name: name, Framework: "soc2", ReportType: "audit_summary", IntervalSeconds: 3600,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Results) != 1 || applied.Results[0].Outcome != api.BaselineFailed || !strings.Contains(applied.Results[0].Error, `another report schedule is named`) {
		t.Fatalf("a baseline schedule under a held name: %+v", applied.Results)
	}
	if after := head(); after != before {
		t.Fatalf("the refused schedules appended %d event(s)", after-before)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("the read model no longer rebuilds: %v", err)
	}

	// A log that already holds such an event rebuilds as live.
	poisoned, err := json.Marshal(projections.ComplianceReportScheduleUpserted{
		ID: "15151515-1515-4515-8515-151515151515", Framework: "soc2", Name: name, ReportType: "audit_summary",
		IntervalSeconds: 3600, Enabled: true, Delivery: "audit_export",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{Type: projections.EventComplianceReportScheduleUpserted, TenantID: h.tenant, Data: poisoned}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("a log holding a pre-check duplicate does not rebuild: %v", err)
	}
	schedules, err := h.store.ListComplianceReportSchedulesPage(t.Context(), h.tenant, store.ZeroUUID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(schedules) != 1 || schedules[0].ID != first.ID || schedules[0].Name != name {
		t.Fatalf("schedules after the rebuild = %+v, want only the first", schedules)
	}
}
