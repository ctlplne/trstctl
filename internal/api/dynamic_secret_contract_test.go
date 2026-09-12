// SPDX-License-Identifier: MPL-2.0

package api_test

import "testing"

func TestDynamicSecretContractsExposeProviderConfigurationAndEffectFreePreview(t *testing.T) {
	doc := fetchSpec(t)
	paths := doc["paths"].(map[string]any)
	providersPath, ok := paths["/api/v1/secrets/leases/providers"].(map[string]any)
	if !ok {
		t.Fatal("dynamic-secret contract does not expose the tenant provider catalog")
	}
	providersOperation := providersPath["get"].(map[string]any)
	if providersOperation["operationId"] != "listDynamicSecretProviders" || providersOperation["x-trstctl-permission"] != "secrets:read" {
		t.Fatalf("dynamic-secret provider catalog operation = %#v", providersOperation)
	}
	previewPath, ok := paths["/api/v1/secrets/leases/preview"].(map[string]any)
	if !ok {
		t.Fatal("dynamic-secret contract does not expose an effect-free preview route")
	}
	previewOperation := previewPath["post"].(map[string]any)
	if previewOperation["operationId"] != "previewDynamicSecretLease" || previewOperation["x-trstctl-permission"] != "secrets:write" {
		t.Fatalf("dynamic-secret preview operation = %#v", previewOperation)
	}

	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	request := schemas["DynamicLeaseRequest"].(map[string]any)
	if request["properties"].(map[string]any)["preview_fingerprint"] == nil {
		t.Fatalf("dynamic lease issue request does not accept reviewed evidence: %#v", request)
	}
	catalog := schemas["DynamicSecretProviderCatalog"].(map[string]any)
	for _, field := range []string{"capability", "configuration_mode", "configuration_changes_require_restart", "secret_delivery", "supported_providers", "configured_providers", "blockers", "secret_data_handling"} {
		if !dynamicSecretContractContains(catalog["required"], field) {
			t.Fatalf("provider catalog does not require %s: %#v", field, catalog["required"])
		}
	}
	preview := schemas["DynamicLeasePreview"].(map[string]any)
	for _, field := range []string{"capability", "operation", "ready", "effect_free", "provider_id", "provider_type", "role", "effective_ttl_seconds", "maximum_ttl_seconds", "request_fingerprint", "preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "secret_data_handling"} {
		if !dynamicSecretContractContains(preview["required"], field) {
			t.Fatalf("dynamic lease preview does not require %s: %#v", field, preview["required"])
		}
	}
}

func dynamicSecretContractContains(value any, want string) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestDynamicLeaseContractDistinguishesRevocationFromProviderCompletion(t *testing.T) {
	doc := fetchSpec(t)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	lease := schemas["DynamicLease"].(map[string]any)
	properties := lease["properties"].(map[string]any)
	for _, field := range []string{"hard_expires_at", "revocation_status", "revoked_at", "revocation_completed_at"} {
		if properties[field] == nil {
			t.Errorf("lease metadata hides durable %s", field)
		}
		if dynamicSecretContractContains(lease["required"], field) {
			t.Errorf("%s must remain optional for older immutable operation receipts", field)
		}
	}
}
