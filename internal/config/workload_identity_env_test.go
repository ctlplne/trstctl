// SPDX-License-Identifier: MPL-2.0

package config

import (
	"strings"
	"testing"
)

// Container-first deployments configure the control plane with environment
// variables. A workload mint that exists only in a JSON/YAML config file is not
// operable from the shipped Compose pattern.
func TestWorkloadIdentityAndSSHEnvironmentOverlay(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_ATTESTED_ISSUANCE_ENABLED":             "true",
		"TRSTCTL_ATTESTED_ISSUANCE_TRUST_DOMAIN":        "demo.trstctl.local",
		"TRSTCTL_ATTESTED_ISSUANCE_DEFAULT_TTL":         "10m",
		"TRSTCTL_ATTESTED_ISSUANCE_MAX_TTL":             "1h",
		"TRSTCTL_EPHEMERAL_ISSUANCE_ENABLED":            "true",
		"TRSTCTL_EPHEMERAL_ISSUANCE_TRUST_DOMAIN":       "demo.trstctl.local",
		"TRSTCTL_EPHEMERAL_ISSUANCE_DEFAULT_TTL":        "5m",
		"TRSTCTL_EPHEMERAL_ISSUANCE_MAX_TTL":            "30m",
		"TRSTCTL_EPHEMERAL_ISSUANCE_APPROVAL_TTL":       "10m",
		"TRSTCTL_EPHEMERAL_ISSUANCE_REQUIRED_APPROVALS": "1",
		"TRSTCTL_PROTOCOLS_SSH_ENABLED":                 "true",
		"TRSTCTL_PROTOCOLS_SSH_TENANT_ID":               "11111111-1111-4111-8111-111111111111",
	}
	cfg := Config{}
	cfg.applyEnv(func(key string) string { return env[key] })
	if !cfg.AttestedIssuance.Enabled || cfg.AttestedIssuance.TrustDomain != "demo.trstctl.local" ||
		cfg.AttestedIssuance.DefaultTTL != "10m" || cfg.AttestedIssuance.MaxTTL != "1h" {
		t.Fatalf("attested issuance environment overlay = %+v", cfg.AttestedIssuance)
	}
	if !cfg.EphemeralIssuance.Enabled || cfg.EphemeralIssuance.TrustDomain != "demo.trstctl.local" ||
		cfg.EphemeralIssuance.DefaultTTL != "5m" || cfg.EphemeralIssuance.MaxTTL != "30m" ||
		cfg.EphemeralIssuance.ApprovalTTL != "10m" || cfg.EphemeralIssuance.RequiredApprovals != 1 {
		t.Fatalf("ephemeral issuance environment overlay = %+v", cfg.EphemeralIssuance)
	}
	if !cfg.Protocols.SSH.Enabled || cfg.Protocols.SSH.TenantID != env["TRSTCTL_PROTOCOLS_SSH_TENANT_ID"] {
		t.Fatalf("SSH environment overlay = %+v", cfg.Protocols.SSH)
	}
}

func TestEphemeralIssuanceValidationFailsClosed(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]EphemeralIssuance{
		"missing trust domain": {Enabled: true},
		"invalid ttl":          {Enabled: true, TrustDomain: "example.org", MaxTTL: "forever"},
		"default above max":    {Enabled: true, TrustDomain: "example.org", DefaultTTL: "2h", MaxTTL: "1h"},
		"negative approvals":   {Enabled: true, TrustDomain: "example.org", RequiredApprovals: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateEphemeralIssuance(input); len(err) == 0 {
				t.Fatalf("ephemeral issuance validation accepted %+v", input)
			}
		})
	}
	if errs := validateEphemeralIssuance(EphemeralIssuance{
		Enabled: true, TrustDomain: "example.org", DefaultTTL: "5m", MaxTTL: "1h",
		ApprovalTTL: "15m", RequiredApprovals: 2,
	}); len(errs) != 0 {
		t.Fatalf("valid ephemeral issuance rejected: %s", strings.Join(errorStrings(errs), "; "))
	}
}

func errorStrings(errs []error) []string {
	out := make([]string, len(errs))
	for i, err := range errs {
		out[i] = err.Error()
	}
	return out
}
