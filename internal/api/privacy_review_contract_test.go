// SPDX-License-Identifier: MPL-2.0

package api

import "testing"

func TestPrivacyReviewAndRecoveryContractF79(t *testing.T) {
	doc := New(nil, nil, nil).Spec()
	want := map[string]struct {
		operationID string
		request     string
		response    string
	}{
		"/api/v1/privacy/subject-erasures/preview": {
			operationID: "previewPrivacySubjectErasure",
			request:     "PrivacySubjectErasureRequest",
			response:    "PrivacySubjectErasurePreview",
		},
		"/api/v1/privacy/retention-runs/preview": {
			operationID: "previewPrivacyRetention",
			response:    "PrivacyRetentionPreview",
		},
	}
	for path, expected := range want {
		op := doc.Paths[path]["post"]
		if op == nil || op.OperationID != expected.operationID || op.XPermission != "privacy:write" {
			t.Errorf("privacy preview route %s is incomplete: %+v", path, op)
			continue
		}
		for _, route := range New(nil, nil, nil).routes() {
			if route.opID == expected.operationID && route.mutation {
				t.Errorf("effect-free privacy preview %s was registered as a mutation", expected.operationID)
			}
		}
		if op.Responses["200"].Content["application/json"].Schema.Ref != "#/components/schemas/"+expected.response {
			t.Errorf("privacy preview %s response schema = %+v", expected.operationID, op.Responses["200"])
		}
	}

	for _, name := range []string{"PrivacySubjectErasurePreview", "PrivacyRetentionPreview"} {
		schema := doc.Components.Schemas[name]
		if schema == nil {
			t.Fatalf("missing %s schema", name)
		}
		for _, field := range []string{
			"capability", "operation", "ready", "effect_free", "request_fingerprint",
			"required_permission", "prerequisites", "blockers", "warnings", "preview_writes",
			"preview_external_effects", "execute_writes", "execute_external_effects",
			"recovery_steps", "verification_steps", "secret_data_handling",
		} {
			if schema.Properties[field] == nil {
				t.Errorf("%s missing %s", name, field)
			}
		}
	}
	for _, field := range []string{"normalized_request", "subject_ref", "counts", "total_records", "archive_attestations", "active_legal_holds"} {
		if doc.Components.Schemas["PrivacySubjectErasurePreview"].Properties[field] == nil {
			t.Errorf("PrivacySubjectErasurePreview missing %s", field)
		}
	}
	for _, field := range []string{"reviewed_at", "cutoffs", "counts", "total_records"} {
		if doc.Components.Schemas["PrivacyRetentionPreview"].Properties[field] == nil {
			t.Errorf("PrivacyRetentionPreview missing %s", field)
		}
	}
}

func TestPrivacySubjectExportCountTotalDoesNotDoubleCountReadModelBreakdowns(t *testing.T) {
	counts := map[string]int{
		"owners":              1,
		"read_models":         2,
		"discovery_findings":  1,
		"incident_executions": 1,
	}
	if got := privacySubjectExportCountTotal(counts); got != 3 {
		t.Fatalf("privacySubjectExportCountTotal() = %d, want 3 distinct records", got)
	}
}

func TestPrivacyHistoryMutationsDoNotInvertTenantCryptoAndHistoryFences(t *testing.T) {
	wantExempt := map[string]bool{
		"erasePrivacySubject":     false,
		"enforcePrivacyRetention": false,
	}
	for _, route := range New(nil, nil, nil).routes() {
		if _, ok := wantExempt[route.opID]; !ok {
			continue
		}
		wantExempt[route.opID] = true
		if !route.mutation || !tenantCryptoExemptOperation(route.opID) {
			t.Errorf("%s does not use the history-safe mutation route contract", route.opID)
		}
	}
	for operationID, found := range wantExempt {
		if !found {
			t.Errorf("missing privacy history mutation route %s", operationID)
		}
	}

	// Structured reviews and ordinary privacy reads do not acquire the history
	// rewrite lock, so they keep the normal fail-closed tenant crypto guard.
	for _, operationID := range []string{
		"previewPrivacySubjectErasure",
		"previewPrivacyRetention",
		"listPrivacySubjectErasures",
		"listPrivacyRetentionRuns",
	} {
		if tenantCryptoExemptOperation(operationID) {
			t.Errorf("%s unexpectedly bypasses the route-wide tenant crypto guard", operationID)
		}
	}
}
