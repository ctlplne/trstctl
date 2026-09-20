// SPDX-License-Identifier: BUSL-1.1

package api_test

import "testing"

func TestSecretSyncPreviewContractIsEffectFreeAndMetadataOnly(t *testing.T) {
	doc := fetchSpec(t)
	op := doc["paths"].(map[string]any)["/api/v1/secrets/syncs/preview"].(map[string]any)["post"].(map[string]any)
	if op["operationId"] != "previewSecretSync" || op["x-trstctl-permission"] != "secrets:write" {
		t.Fatalf("secret-sync preview operation = id:%v permission:%v", op["operationId"], op["x-trstctl-permission"])
	}
	if hasRequiredHeaderParam(op, "Idempotency-Key") {
		t.Fatal("effect-free secret-sync preview declares a mutation Idempotency-Key")
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	preview := schemas["SecretSyncPreview"].(map[string]any)
	properties := preview["properties"].(map[string]any)
	for _, forbidden := range []string{"value", "secret_value", "credential", "token", "sealed"} {
		if properties[forbidden] != nil {
			t.Fatalf("secret-sync preview exposes forbidden value-bearing property %q", forbidden)
		}
	}
	for _, required := range []string{
		"capability", "operation", "ready", "effect_free", "name", "secret_version", "target", "remote_key",
		"required_permission", "blockers", "preview_reads", "preview_writes", "preview_external_effects",
		"execute_writes", "execute_external_effects", "recovery_steps", "verification_steps", "cli_argv", "secret_data_handling",
	} {
		if !pkiContractContains(preview["required"], required) {
			t.Fatalf("SecretSyncPreview does not require %q: %#v", required, preview["required"])
		}
	}
}
