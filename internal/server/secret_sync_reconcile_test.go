// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
)

// Production targets are built from configuration and construct their concrete
// pusher per delivery. The readback capability must therefore be answered from
// the configured type, and the catalog must agree, so the console, the API and
// the worker all tell the operator the same thing about a target.
func TestConfiguredSecretSyncTargetsReportReceiverReconciliationFromTheirType(t *testing.T) {
	capable := map[string]bool{}
	for _, entry := range secretsync.ProviderCatalog() {
		for _, capability := range entry.Capabilities {
			if capability == secretsync.CapabilityReceiverReconcile {
				capable[entry.ID] = true
			}
		}
	}
	for _, tc := range []struct {
		configType string
		want       bool
	}{
		{"vault-kv-v2", true}, {"terraform-cloud-opentofu", true}, {"gcp-secret-manager", true},
		{"azure-key-vault", true}, {"kubernetes-secrets", true},
		{"github-actions", false}, {"gitlab-ci", false}, {"vercel", false}, {"generic-ci-json", false},
		{"aws-secrets-manager", false},
	} {
		pusher := newConfiguredSyncPusher(config.SecretSyncTargetConfig{TenantID: "t", ID: "x", Type: tc.configType}, integrationCredentialResolver{}, nil, nil, nil, nil)
		target := secretsync.NewConfiguredTarget("x", tc.configType, false, pusher)
		if got := target.CanReconcile(); got != tc.want {
			t.Fatalf("%s CanReconcile = %v, want %v", tc.configType, got, tc.want)
		}
		if got := capable[target.ProviderID()]; got != tc.want {
			t.Fatalf("%s catalog receiver-reconcile = %v, want %v", tc.configType, got, tc.want)
		}
	}
}
