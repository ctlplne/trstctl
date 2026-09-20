// SPDX-License-Identifier: BUSL-1.1

package api

import "testing"

func TestComplianceReportScheduleReviewAndRecoveryContractF62(t *testing.T) {
	doc := New(nil, nil, nil).Spec()
	preview := doc.Paths["/api/v1/compliance/report-schedules/preview"]["post"]
	if preview == nil || preview.OperationID != "previewComplianceReportSchedule" || preview.XPermission != "audit:write" {
		t.Fatalf("compliance report-schedule preview route is incomplete: %+v", preview)
	}
	for _, route := range New(nil, nil, nil).routes() {
		if route.opID == "previewComplianceReportSchedule" && route.mutation {
			t.Fatal("effect-free compliance report-schedule preview was registered as a mutation")
		}
	}

	for path, operationID := range map[string]string{
		"/api/v1/compliance/report-schedules/{id}/pause":  "pauseComplianceReportSchedule",
		"/api/v1/compliance/report-schedules/{id}/resume": "resumeComplianceReportSchedule",
	} {
		op := doc.Paths[path]["post"]
		if op == nil || op.OperationID != operationID || op.XPermission != "audit:write" {
			t.Errorf("compliance report-schedule recovery route %s is incomplete: %+v", path, op)
		}
	}

	schema := doc.Components.Schemas["ComplianceReportSchedulePreview"]
	if schema == nil {
		t.Fatal("missing ComplianceReportSchedulePreview schema")
	}
	for _, field := range []string{
		"capability", "operation", "ready", "effect_free", "request_fingerprint",
		"required_permission", "normalized_request", "blockers", "warnings",
		"preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects",
		"recovery_steps", "verification_steps", "secret_data_handling",
	} {
		if schema.Properties[field] == nil {
			t.Errorf("ComplianceReportSchedulePreview missing %s", field)
		}
	}
}
