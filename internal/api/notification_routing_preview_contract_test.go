// SPDX-License-Identifier: BUSL-1.1

package api

import "testing"

func TestNotificationRoutingPolicyPreviewContractIsEffectFreeAndRecoveryAware(t *testing.T) {
	doc := New(nil, nil, nil).Spec()
	op := doc.Paths["/api/v1/notification-routing-policies/preview"]["post"]
	if op == nil || op.OperationID != "previewNotificationRoutingPolicy" || op.XPermission != "notifications:write" {
		t.Fatalf("notification routing-policy preview route is incomplete: %+v", op)
	}
	for _, route := range New(nil, nil, nil).routes() {
		if route.opID == "previewNotificationRoutingPolicy" && route.mutation {
			t.Fatal("effect-free notification routing-policy preview was registered as a mutation")
		}
	}
	schema := doc.Components.Schemas["NotificationRoutingPolicyPreview"]
	if schema == nil {
		t.Fatal("missing NotificationRoutingPolicyPreview schema")
	}
	for _, field := range []string{
		"capability", "operation", "ready", "effect_free", "request_fingerprint",
		"name", "scope_kind", "channels_by_severity", "default_channels",
		"configured_channels", "missing_channels", "blockers",
		"preview_writes", "preview_external_effects", "execute_writes", "execute_external_effects",
		"recovery_steps", "verification_steps", "secret_data_handling",
	} {
		if schema.Properties[field] == nil {
			t.Errorf("NotificationRoutingPolicyPreview missing %s", field)
		}
	}
	for _, forbidden := range []string{"credential_ref", "credential", "secret", "token", "password"} {
		if schema.Properties[forbidden] != nil {
			t.Errorf("NotificationRoutingPolicyPreview exposes value-bearing field %s", forbidden)
		}
	}
}
