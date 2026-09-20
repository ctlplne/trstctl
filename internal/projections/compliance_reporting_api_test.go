// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestComplianceInventoryReportingCAPOBS02 proves CAP-OBS-02 is served: report
// schedules are tenant-scoped, idempotent mutations, and the inventory report
// enumerates the served API/CLI evidence instead of relying on documentation.
func TestComplianceInventoryReportingCAPOBS02(t *testing.T) {
	srv, _ := newGraphAPI(t)

	req := map[string]any{
		"name":             "Quarterly SOC 2 inventory",
		"framework":        "soc2",
		"report_type":      "inventory_snapshot",
		"interval_seconds": 90 * 24 * 60 * 60,
		"enabled":          true,
		"delivery":         "audit_export",
		"recipient_ref":    "audit-vault",
	}
	status, _, body := do(t, srv, http.MethodPost, "/api/v1/compliance/report-schedules/preview", reqOpts{
		tenant: tenantA,
		body:   req,
	})
	if status != http.StatusOK {
		t.Fatalf("preview report schedule = %d: %s", status, body)
	}
	var preview struct {
		Capability         string         `json:"capability"`
		Operation          string         `json:"operation"`
		Ready              bool           `json:"ready"`
		EffectFree         bool           `json:"effect_free"`
		RequestFingerprint string         `json:"request_fingerprint"`
		NormalizedRequest  map[string]any `json:"normalized_request"`
		PreviewWrites      []string       `json:"preview_writes"`
		PreviewEffects     []string       `json:"preview_external_effects"`
		RecoverySteps      []string       `json:"recovery_steps"`
		VerificationSteps  []string       `json:"verification_steps"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode schedule preview: %v", err)
	}
	if preview.Capability != "F62" || preview.Operation != "create_report_schedule" || !preview.Ready || !preview.EffectFree ||
		preview.RequestFingerprint == "" || len(preview.PreviewWrites) != 0 || len(preview.PreviewEffects) != 0 ||
		len(preview.RecoverySteps) == 0 || len(preview.VerificationSteps) == 0 || preview.NormalizedRequest["delivery"] != "audit_export" {
		t.Fatalf("schedule preview = %+v, want exact effect-free ready plan", preview)
	}
	status, _, body = do(t, srv, http.MethodGet, "/api/v1/compliance/report-schedules", reqOpts{tenant: tenantA})
	var afterPreview struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &afterPreview); err != nil {
		t.Fatalf("decode report schedules after preview: %v", err)
	}
	if status != http.StatusOK || len(afterPreview.Items) != 0 {
		t.Fatalf("preview mutated report schedules = %d: %s", status, body)
	}
	tightLoop := map[string]any{
		"name":             "Every second",
		"framework":        "soc2",
		"report_type":      "inventory_snapshot",
		"interval_seconds": 1,
	}
	status, _, body = do(t, srv, http.MethodPost, "/api/v1/compliance/report-schedules/preview", reqOpts{tenant: tenantA, body: tightLoop})
	if status != http.StatusBadRequest {
		t.Fatalf("tight-loop schedule preview = %d: %s", status, body)
	}

	status, _, body = do(t, srv, http.MethodPost, "/api/v1/compliance/report-schedules", reqOpts{
		tenant: tenantA,
		idem:   "cap-obs-02-schedule",
		body:   req,
	})
	if status != http.StatusCreated {
		t.Fatalf("create report schedule = %d: %s", status, body)
	}
	var created struct {
		ID              string `json:"id"`
		Framework       string `json:"framework"`
		ReportType      string `json:"report_type"`
		IntervalSeconds int    `json:"interval_seconds"`
		Enabled         bool   `json:"enabled"`
		Delivery        string `json:"delivery"`
		RecipientRef    string `json:"recipient_ref"`
		NextRunAt       string `json:"next_run_at"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created schedule: %v", err)
	}
	if created.ID == "" || created.Framework != "soc2" || created.ReportType != "inventory_snapshot" ||
		created.IntervalSeconds != 90*24*60*60 || !created.Enabled || created.Delivery != "audit_export" ||
		created.RecipientRef != "audit-vault" || created.NextRunAt == "" {
		t.Fatalf("created schedule = %+v, want served SOC 2 inventory schedule", created)
	}

	unsupportedDelivery := map[string]any{
		"name":             "Webhook SOC 2 inventory",
		"framework":        "soc2",
		"report_type":      "inventory_snapshot",
		"interval_seconds": 24 * 60 * 60,
		"delivery":         "webhook",
	}
	status, _, body = do(t, srv, http.MethodPost, "/api/v1/compliance/report-schedules", reqOpts{
		tenant: tenantA,
		idem:   "cap-obs-02-unsupported-delivery",
		body:   unsupportedDelivery,
	})
	if status != http.StatusBadRequest {
		t.Fatalf("unsupported report delivery = %d: %s", status, body)
	}

	replayStatus, _, replayBody := do(t, srv, http.MethodPost, "/api/v1/compliance/report-schedules", reqOpts{
		tenant: tenantA,
		idem:   "cap-obs-02-schedule",
		body:   req,
	})
	if replayStatus != http.StatusCreated {
		t.Fatalf("replay report schedule = %d: %s", replayStatus, replayBody)
	}
	var replayed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(replayBody, &replayed); err != nil {
		t.Fatalf("decode replayed schedule: %v", err)
	}
	if replayed.ID != created.ID {
		t.Fatalf("idempotent replay id = %q, want %q", replayed.ID, created.ID)
	}

	status, _, body = do(t, srv, http.MethodGet, "/api/v1/compliance/report-schedules", reqOpts{tenant: tenantA})
	if status != http.StatusOK {
		t.Fatalf("list report schedules = %d: %s", status, body)
	}
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode schedule list: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].ID != created.ID {
		t.Fatalf("listed schedules = %+v, want created schedule", list.Items)
	}

	status, _, body = do(t, srv, http.MethodGet, "/api/v1/compliance/inventory-report", reqOpts{tenant: tenantA})
	if status != http.StatusOK {
		t.Fatalf("inventory report = %d: %s", status, body)
	}
	var report struct {
		Capability string `json:"capability"`
		Summary    struct {
			FrameworksSupported    int `json:"frameworks_supported"`
			ReportSchedules        int `json:"report_schedules"`
			EnabledReportSchedules int `json:"enabled_report_schedules"`
			InventoryRows          int `json:"inventory_rows"`
		} `json:"summary"`
		Frameworks   []string `json:"frameworks"`
		ReportTypes  []string `json:"report_types"`
		Routes       []string `json:"routes"`
		EvidenceRefs []string `json:"evidence_refs"`
		Schedules    []struct {
			ID         string `json:"id"`
			Framework  string `json:"framework"`
			ReportType string `json:"report_type"`
			Enabled    bool   `json:"enabled"`
		} `json:"schedules"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("decode inventory report: %v", err)
	}
	if report.Capability != "CAP-OBS-02" {
		t.Fatalf("capability = %q, want CAP-OBS-02", report.Capability)
	}
	if report.Summary.FrameworksSupported < 10 || report.Summary.ReportSchedules != 1 ||
		report.Summary.EnabledReportSchedules != 1 || report.Summary.InventoryRows < 1 {
		t.Fatalf("summary = %+v, want served framework coverage and one enabled schedule", report.Summary)
	}
	if !hasString(report.Frameworks, "soc2") || !hasString(report.ReportTypes, "inventory_snapshot") ||
		!hasString(report.Routes, "POST /api/v1/compliance/report-schedules") ||
		!hasString(report.Routes, "GET /api/v1/compliance/inventory-report") {
		t.Fatalf("report coverage missing served framework/type/route evidence: %+v", report)
	}
	if len(report.EvidenceRefs) == 0 || len(report.Schedules) != 1 || report.Schedules[0].ID != created.ID {
		t.Fatalf("report missing evidence or schedule enumeration: %+v", report)
	}

	for _, action := range []struct {
		name        string
		wantEnabled bool
	}{
		{name: "pause", wantEnabled: false},
		{name: "resume", wantEnabled: true},
	} {
		status, _, body = do(t, srv, http.MethodPost, "/api/v1/compliance/report-schedules/"+created.ID+"/"+action.name, reqOpts{
			tenant: tenantA,
			idem:   "cap-obs-02-" + action.name,
		})
		if status != http.StatusOK {
			t.Fatalf("%s report schedule = %d: %s", action.name, status, body)
		}
		var changed struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.Unmarshal(body, &changed); err != nil {
			t.Fatalf("decode %s schedule: %v", action.name, err)
		}
		if changed.ID != created.ID || changed.Enabled != action.wantEnabled {
			t.Fatalf("%s schedule = %+v, want enabled=%t", action.name, changed, action.wantEnabled)
		}
	}
}
