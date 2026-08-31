// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

// TestAuditEndpointExposesFeatureActionParams is the COVER-008 wiring acceptance on
// the served API: the audit query endpoints must advertise the feature_id and action
// query parameters in the OpenAPI 3.1 contract, so an integrator can discover and use
// the catalog-driven audit filter. It fails before the params were added to the route
// table and passes after.
func TestAuditEndpointExposesFeatureActionParams(t *testing.T) {
	raw, err := json.Marshal(api.New(nil, nil, nil).Spec())
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Parameters  []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}

	for _, path := range []string{"/api/v1/audit/events", "/api/v1/audit/export"} {
		get, ok := doc.Paths[path]["get"]
		if !ok {
			t.Fatalf("spec missing GET %s", path)
		}
		have := map[string]bool{}
		for _, p := range get.Parameters {
			if p.In == "query" {
				have[p.Name] = true
			}
		}
		for _, want := range []string{"feature_id", "action", "tool"} {
			if !have[want] {
				t.Errorf("GET %s (%s) is missing the %q query parameter for catalog-driven audit filtering (COVER-008)",
					path, get.OperationID, want)
			}
		}
	}
}
