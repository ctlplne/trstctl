// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// TestLDAPStartTLSIsGenericLDAPOnlyA239L3: start_tls belongs to a generic LDAP
// provider; it can't be combined with allow_plaintext (there is no fallback)
// or with active_directory (which keeps verified LDAPS), and no other type
// takes it.
func TestLDAPStartTLSIsGenericLDAPOnlyA239L3(t *testing.T) {
	const (
		tenant = "11111111-1111-1111-1111-111111111111"
		ref    = "file:/var/lib/trstctl/fixtures/credential"
	)
	valid := func() DynamicSecretProviderConfig {
		return DynamicSecretProviderConfig{
			TenantID: tenant, ID: "ldap", Type: "ldap", Addr: "ldap.lab.test:389", StartTLS: true,
			BindDN: "cn=admin,dc=lab,dc=test", PasswordRef: ref, UsersDN: "ou=leases,dc=lab,dc=test",
			AllowedRoles: []string{"readonly"}, RoleBindings: map[string]string{"readonly": "cn=readers,ou=groups,dc=lab,dc=test"}, MaxTTL: "1h",
		}
	}
	validate := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := validate(valid()); err != nil {
		t.Fatalf("a StartTLS LDAP provider: %v", err)
	}
	plaintext := valid()
	plaintext.Addr, plaintext.AllowPlaintext = "10.0.0.5:389", true
	if err := validate(plaintext); err == nil || !strings.Contains(err.Error(), "start_tls and allow_plaintext are exclusive") {
		t.Fatalf("start_tls with allow_plaintext: %v", err)
	}
	other := DynamicSecretProviderConfig{
		TenantID: tenant, ID: "pg", Type: "postgresql", AdminDSNRef: ref,
		AllowedRoles: []string{"reader"}, StartTLS: true,
	}
	if err := validate(other); err == nil || !strings.Contains(err.Error(), "start_tls is only valid for ldap") {
		t.Fatalf("start_tls on a postgresql provider: %v", err)
	}
	if errs := validateLDAPProvider("dynamic_providers[0]", DynamicSecretProviderConfig{Type: "ldap", StartTLS: true, DirectoryMode: "active_directory"}); !strings.Contains(fmtErrors(errs), "active_directory uses verified LDAPS") {
		t.Fatalf("start_tls in active_directory mode: %v", errs)
	}
}

func fmtErrors(errs []error) string {
	var b strings.Builder
	for _, err := range errs {
		b.WriteString(err.Error())
		b.WriteString("\n")
	}
	return b.String()
}
