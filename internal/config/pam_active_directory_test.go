// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"path/filepath"
	"testing"
)

func TestADModeRequiresStaticTLSAndExactAccountBindings(t *testing.T) {
	ref := "file:" + filepath.Join(t.TempDir(), "admin")
	good := DynamicSecretProviderConfig{TenantID: "54700000-0000-4000-8000-000000000001", ID: "directory", Type: "ldap", DirectoryMode: "active_directory", Addr: "directory.example:636", BindDN: "CN=admin,DC=example,DC=test", PasswordRef: ref, UsersDN: "OU=services,DC=example,DC=test", RoleBindings: map[string]string{"directory/service": "CN=service,OU=services,DC=example,DC=test"}, AllowedRoles: []string{"directory/service"}, AllowStaticRotation: true, MaxTTL: "1h"}
	validate := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := validate(good); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DynamicSecretProviderConfig){func(c *DynamicSecretProviderConfig) { c.DirectoryMode = "unknown" }, func(c *DynamicSecretProviderConfig) { c.AllowStaticRotation = false }, func(c *DynamicSecretProviderConfig) { c.AllowPlaintext = true; c.Addr = "127.0.0.1:389" }, func(c *DynamicSecretProviderConfig) {
		c.RoleBindings = map[string]string{"directory/service": "CN=foreign,DC=foreign,DC=test"}
	}, func(c *DynamicSecretProviderConfig) { c.Type = "unix" }} {
		bad := good
		change(&bad)
		if validate(bad) == nil {
			t.Fatal("unsafe AD configuration accepted")
		}
	}
}
