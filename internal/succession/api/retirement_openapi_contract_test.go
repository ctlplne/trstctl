// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"testing"

	coreapi "trstctl.com/trstctl/internal/api"
)

func TestRetirementOpenAPIModelsAcceptedRosterAndRequiredIdentity(t *testing.T) {
	spec := coreapi.New(nil, nil, nil,
		coreapi.WithLicensedRoutes(Routes(nil)...),
		coreapi.WithLicensedSchemas(schemas()),
	).Spec()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/pcas/chain", "/api/v1/pcas/rewrap", "/api/v1/pcas/retirement",
		"/api/v1/pcas/checkpoints", "/api/v1/pcas/posture",
	} {
		read := paths[path].(map[string]any)["get"].(map[string]any)
		identityRequired := false
		for _, item := range read["parameters"].([]any) {
			param := item.(map[string]any)
			if param["in"] == "query" && param["name"] == "identity_id" {
				identityRequired = param["required"] == true
			}
		}
		if !identityRequired {
			t.Errorf("GET %s must mark identity_id required; its served handler rejects absence", path)
		}
	}

	components := doc["components"].(map[string]any)["schemas"].(map[string]any)
	for _, name := range []string{"PCASRetirementPolicyRequest", "PCASRetirementPolicy"} {
		policy := components[name].(map[string]any)
		roster := policy["properties"].(map[string]any)["roster"].(map[string]any)
		if roster["type"] != "array" {
			t.Errorf("%s roster type = %v, want array of relying-party public keys", name, roster["type"])
			continue
		}
		member := roster["items"].(map[string]any)
		if member["type"] != "object" {
			t.Errorf("%s roster member type = %v, want object", name, member["type"])
			continue
		}
		properties := member["properties"].(map[string]any)
		if properties["relying_party"].(map[string]any)["type"] != "string" ||
			properties["public_der"].(map[string]any)["type"] != "string" {
			t.Errorf("%s roster member = %v, want relying_party and public_der strings", name, properties)
		}
	}
}
