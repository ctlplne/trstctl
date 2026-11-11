// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// TestSSHCertificateProviderNamesEveryRolesCertificateA239L11: an
// ssh-certificate provider signs with the control plane's SSH CA, so it takes
// no endpoint and no static rotation; every allowed role names the principals
// its certificates carry (one name each), user or host; ssh_roles names only
// allowed roles and belongs to this type alone.
func TestSSHCertificateProviderNamesEveryRolesCertificateA239L11(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	valid := func() DynamicSecretProviderConfig {
		return DynamicSecretProviderConfig{
			TenantID: tenant, ID: "ssh", Type: "ssh-certificate", MaxTTL: "1h", AllowedRoles: []string{"deploy", "hosts"},
			SSHRoles: map[string]SSHCertificateRole{
				"deploy": {Principals: []string{"deploy"}, Extensions: map[string]string{"permit-pty": ""}},
				"hosts":  {CertificateType: "host", Principals: []string{"web-1.internal", "web-1"}},
			},
		}
	}
	validate := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := validate(valid()); err != nil {
		t.Fatalf("a valid ssh-certificate provider: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"a role without a certificate": {func(c *DynamicSecretProviderConfig) { delete(c.SSHRoles, "hosts") }, `needs ssh_roles["hosts"]`},
		"no principals": {func(c *DynamicSecretProviderConfig) {
			c.SSHRoles["deploy"] = SSHCertificateRole{}
		}, "must name at least one principal"},
		"a principal list in one name": {func(c *DynamicSecretProviderConfig) {
			c.SSHRoles["deploy"] = SSHCertificateRole{Principals: []string{"deploy,root"}}
		}, "one name with no spaces or commas"},
		"an unknown certificate type": {func(c *DynamicSecretProviderConfig) {
			c.SSHRoles["deploy"] = SSHCertificateRole{CertificateType: "both", Principals: []string{"deploy"}}
		}, "certificate_type must be user or host"},
		"a certificate for a role not allowed": {func(c *DynamicSecretProviderConfig) {
			c.SSHRoles["admin"] = SSHCertificateRole{Principals: []string{"admin"}}
		}, `ssh_roles["admin"] is not an allowed role`},
		"an endpoint":     {func(c *DynamicSecretProviderConfig) { c.Endpoint = "https://ca.example.test" }, "takes no endpoint"},
		"static rotation": {func(c *DynamicSecretProviderConfig) { c.AllowStaticRotation = true }, "no static rotation"},
	} {
		c := valid()
		tc.mutate(&c)
		if err := validate(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := DynamicSecretProviderConfig{
		TenantID: tenant, ID: "pg", Type: "postgresql", AdminDSNRef: "file:/var/lib/trstctl/fixtures/credential",
		AllowedRoles: []string{"reader"}, SSHRoles: map[string]SSHCertificateRole{"reader": {Principals: []string{"deploy"}}},
	}
	if err := validate(other); err == nil || !strings.Contains(err.Error(), "ssh_roles is only valid for ssh-certificate") {
		t.Fatalf("ssh_roles on a postgresql provider: %v", err)
	}
}
