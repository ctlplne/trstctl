// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"path/filepath"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/accessdesktop"
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

func TestADDesktopRequiresDeclaredLogonNames(t *testing.T) {
	const account = "CN=service,OU=services,DC=example,DC=test"
	cfg := DynamicSecretProviderConfig{TenantID: "54800000-0000-4000-8000-000000000001", ID: "ad", Type: "ldap", DirectoryMode: "active_directory", Addr: "ad.example:636", BindDN: "CN=reader,DC=example,DC=test", PasswordRef: "file:" + filepath.Join(t.TempDir(), "admin"), UsersDN: "OU=services,DC=example,DC=test", AllowedRoles: []string{"desktop/service"}, RoleBindings: map[string]string{"desktop/service": account}, AllowStaticRotation: true, MaxTTL: "1h", Desktop: &accessdesktop.Binding{Address: "desktop.example:3389", CertificateSHA256: strings.Repeat("ab", 32), Width: 800, Height: 600}}
	check := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if check(cfg) == nil {
		t.Fatal("AD desktop without an explicit logon name accepted")
	}
	cfg.ADLogonNames = map[string]string{account: "service"}
	if err := check(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ADLogonNames[account] = "DOMAIN\\service"
	if check(cfg) == nil {
		t.Fatal("domain override through logon name allowed")
	}
}
