// SPDX-License-Identifier: BUSL-1.1

package api_test

import "testing"

func TestOpenAPIIdentityIssuanceResultRequiresOriginalRequestKey(t *testing.T) {
	doc := fetchSpec(t)
	paths := doc["paths"].(map[string]any)
	operation := paths["/api/v1/identities/{id}/issuance-result"].(map[string]any)["get"].(map[string]any)
	parameters := operation["parameters"].([]any)
	keys := 0
	for _, value := range parameters {
		parameter := value.(map[string]any)
		if parameter["in"] != "query" || parameter["name"] != "request_key" {
			continue
		}
		keys++
		if parameter["required"] != true {
			t.Error("generated clients may omit the exact request key required by the served result handler")
		}
		if schema := parameter["schema"].(map[string]any); schema["type"] != "string" {
			t.Fatalf("request_key schema=%v, want string", schema)
		}
	}
	if keys != 1 {
		t.Fatalf("request_key appears %d times, want exactly once", keys)
	}
	// Required query metadata must not turn unrelated optional filters into
	// new customer prerequisites.
	list := paths["/api/v1/certificates"].(map[string]any)["get"].(map[string]any)
	for _, value := range list["parameters"].([]any) {
		parameter := value.(map[string]any)
		if parameter["in"] == "query" && parameter["required"] == true {
			t.Fatalf("optional certificate filter became required: %v", parameter["name"])
		}
	}
}

// Clients must be able to read a legitimately stopped command without treating
// its terminal state as an unknown response or offering another signing attempt.
func TestOpenAPIIdentityIssuanceResultIncludesCancelledDelivery(t *testing.T) {
	doc := fetchSpec(t)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	properties := schemas["IdentityIssuanceResult"].(map[string]any)["properties"].(map[string]any)
	delivery := properties["delivery"].(map[string]any)["properties"].(map[string]any)
	for name, property := range map[string]any{"state": properties["state"], "delivery.status": delivery["status"]} {
		values := property.(map[string]any)["enum"].([]any)
		found := false
		for _, value := range values {
			if value == "cancelled" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s cannot represent a canceled issuance: %v", name, values)
		}
	}
}
