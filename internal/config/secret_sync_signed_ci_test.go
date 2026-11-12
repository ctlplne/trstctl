// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// OD-12 (B14-L2): a generic CI push target may name a signing key; it must
// be a file:/absolute/path or secret:// reference like the webhook's, and a
// target without one stays valid (the bearer-only push).
func TestGenericCIPushTargetTakesAnOptionalSigningKeyOD12(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	target := SecretSyncTargetConfig{TenantID: tenant, ID: "ci", Type: "generic-ci-json", Endpoint: "https://ci.example.test", Provider: "example-ci"}
	for _, ref := range []string{"", "file:/run/secrets/ci-signing-key", "secret://integrations/ci-signing-key"} {
		target.SigningKeyRef = ref
		if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{target}}, true); err != nil {
			t.Fatalf("signing_key_ref %q: %v", ref, err)
		}
	}
	for _, ref := range []string{"inline-key", "file:relative/key", "secret://"} {
		target.SigningKeyRef = ref
		err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{target}}, true)
		if err == nil || !strings.Contains(err.Error(), "signing_key_ref") {
			t.Fatalf("signing_key_ref %q: %v, want an error naming signing_key_ref", ref, err)
		}
	}
}
