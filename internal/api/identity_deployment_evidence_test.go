// SPDX-License-Identifier: BUSL-1.1

package api_test

import "testing"

func TestOpenAPIIdentityDeploymentEvidenceIsCertificateScopedHistoricalRead(t *testing.T) {
	doc := fetchSpec(t)
	operation := doc["paths"].(map[string]any)["/api/v1/identities/{id}/deployment-evidence"].(map[string]any)["get"].(map[string]any)
	if operation["x-trstctl-permission"] != "certs:read" {
		t.Fatalf("permission=%v", operation["x-trstctl-permission"])
	}
	schema := doc["components"].(map[string]any)["schemas"].(map[string]any)["IdentityDeploymentEvidence"].(map[string]any)
	properties := schema["properties"].(map[string]any)
	for _, field := range []string{"identity_id", "read_at", "receipt", "certificate"} {
		if properties[field] == nil {
			t.Fatalf("missing field %s", field)
		}
	}
}
