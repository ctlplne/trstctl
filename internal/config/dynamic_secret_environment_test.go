// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDynamicProviderSecretEnvironmentPlacementA235L2: a provider's
// secret_environment is "<project>/<environment>", two slugs; anything else
// is refused at startup, and the field reads from the configuration file.
func TestDynamicProviderSecretEnvironmentPlacementA235L2(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "orders", Type: "postgresql",
		AdminDSNRef: "file:/run/secrets/orders-admin-dsn", AllowedRoles: []string{"readonly"}, MaxTTL: "1h"}
	check := func(env string) error {
		c := base
		c.SecretEnvironment = env
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	for _, env := range []string{"", "payments/prod", "pay-2/stage-eu"} {
		if err := check(env); err != nil {
			t.Fatalf("secret_environment %q refused: %v", env, err)
		}
	}
	for _, env := range []string{"payments", "payments/prod/db", "Payments/prod", "payments/", "/prod", "pay ments/prod"} {
		if err := check(env); err == nil || !strings.Contains(err.Error(), "secret_environment") {
			t.Fatalf("secret_environment %q = %v, want a refusal naming the field", env, err)
		}
	}
	var decoded DynamicSecretProviderConfig
	if err := json.Unmarshal([]byte(`{"tenant_id":"t","id":"orders","type":"postgresql","secret_environment":"payments/prod"}`), &decoded); err != nil || decoded.SecretEnvironment != "payments/prod" {
		t.Fatalf("decoded secret_environment = %q, %v", decoded.SecretEnvironment, err)
	}
}
