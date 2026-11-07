// SPDX-License-Identifier: BUSL-1.1
package config

import "testing"

func TestNativeWindowsHostRotationConfigurationA268(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-4111-8111-111111111111", ID: "native-sam", Type: "windows", WindowsHostAgentID: "22222222-2222-4222-8222-222222222222", AllowedRoles: []string{"host/admin"}, RoleBindings: map[string]string{"host/admin": "S-1-5-21-1-2-3-1001"}, AllowStaticRotation: true}
	check := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if e := check(base); e != nil {
		t.Fatal("exact native host binding rejected", e)
	}
	for _, tc := range []struct {
		name string
		edit func(*DynamicSecretProviderConfig)
	}{
		{"another family", func(c *DynamicSecretProviderConfig) { c.Type = "unix" }},
		{"not enrolled", func(c *DynamicSecretProviderConfig) { c.WindowsHostAgentID = "host" }},
		{"no static opt in", func(c *DynamicSecretProviderConfig) { c.AllowStaticRotation = false }},
		{"mixed SSH", func(c *DynamicSecretProviderConfig) { c.Addr = "host.test:22" }},
		{"mixed key", func(c *DynamicSecretProviderConfig) { c.PrivateKeyRef = "file:/owned/reference" }},
		{"paired accounts", func(c *DynamicSecretProviderConfig) {
			c.RotationAccounts = map[string][]string{"host/admin": {"first", "second"}}
		}},
		{"name instead of SID", func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"host/admin": "Administrator"}
		}},
		{"foreign authority", func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"host/admin": "S-1-5-32-544"} }},
		{"unallowed role", func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"host/admin": "S-1-5-21-1-2-3-1001", "other": "S-1-5-21-1-2-3-1002"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.edit(&c)
			if e := check(c); e == nil {
				t.Fatal("ambiguous or non-local native authority accepted")
			}
		})
	}
}
