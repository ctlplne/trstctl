// SPDX-License-Identifier: MPL-2.0

package config

import "testing"

// Container-first deployments configure the control plane with environment
// variables. A workload mint that exists only in a JSON/YAML config file is not
// operable from the shipped Compose pattern.
func TestWorkloadIdentityAndSSHEnvironmentOverlay(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_ATTESTED_ISSUANCE_ENABLED":      "true",
		"TRSTCTL_ATTESTED_ISSUANCE_TRUST_DOMAIN": "demo.trstctl.local",
		"TRSTCTL_ATTESTED_ISSUANCE_DEFAULT_TTL":  "10m",
		"TRSTCTL_ATTESTED_ISSUANCE_MAX_TTL":      "1h",
		"TRSTCTL_PROTOCOLS_SSH_ENABLED":          "true",
		"TRSTCTL_PROTOCOLS_SSH_TENANT_ID":        "11111111-1111-4111-8111-111111111111",
	}
	cfg := Config{}
	cfg.applyEnv(func(key string) string { return env[key] })
	if !cfg.AttestedIssuance.Enabled || cfg.AttestedIssuance.TrustDomain != "demo.trstctl.local" ||
		cfg.AttestedIssuance.DefaultTTL != "10m" || cfg.AttestedIssuance.MaxTTL != "1h" {
		t.Fatalf("attested issuance environment overlay = %+v", cfg.AttestedIssuance)
	}
	if !cfg.Protocols.SSH.Enabled || cfg.Protocols.SSH.TenantID != env["TRSTCTL_PROTOCOLS_SSH_TENANT_ID"] {
		t.Fatalf("SSH environment overlay = %+v", cfg.Protocols.SSH)
	}
}
