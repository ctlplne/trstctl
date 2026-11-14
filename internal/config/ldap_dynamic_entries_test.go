// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// TestLDAPDynamicEntriesIsGenericLDAPOnlyA239L2: dynamic_entries belongs to a
// generic LDAP provider, whose leases are entries it creates; an
// active_directory provider rotates existing accounts the directory must keep,
// and no other type takes it.
func TestLDAPDynamicEntriesIsGenericLDAPOnlyA239L2(t *testing.T) {
	const (
		tenant = "11111111-1111-1111-1111-111111111111"
		ref    = "file:/var/lib/trstctl/fixtures/credential"
	)
	validate := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	ldap := DynamicSecretProviderConfig{
		TenantID: tenant, ID: "ldap", Type: "ldap", Addr: "ldap.lab.test:636", DynamicEntries: true,
		BindDN: "cn=admin,dc=lab,dc=test", PasswordRef: ref, UsersDN: "ou=leases,dc=lab,dc=test",
		AllowedRoles: []string{"readonly"}, RoleBindings: map[string]string{"readonly": "cn=readers,ou=groups,dc=lab,dc=test"}, MaxTTL: "1h",
	}
	if err := validate(ldap); err != nil {
		t.Fatalf("an LDAP provider with dynamic entries: %v", err)
	}
	other := DynamicSecretProviderConfig{
		TenantID: tenant, ID: "pg", Type: "postgresql", AdminDSNRef: ref,
		AllowedRoles: []string{"reader"}, DynamicEntries: true,
	}
	if err := validate(other); err == nil || !strings.Contains(err.Error(), "dynamic_entries is only valid for an ldap provider without directory_mode") {
		t.Fatalf("dynamic_entries on a postgresql provider: %v", err)
	}
	if errs := validateProviderFieldScopes("dynamic_providers[0]", DynamicSecretProviderConfig{Type: "ldap", DynamicEntries: true, DirectoryMode: "active_directory"}); !strings.Contains(fmtErrors(errs), "dynamic_entries is only valid for an ldap provider without directory_mode") {
		t.Fatalf("dynamic_entries in active_directory mode: %v", errs)
	}
}
