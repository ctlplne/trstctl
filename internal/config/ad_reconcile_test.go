// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestADReconcileRequiresDistinctPinnedPrincipalAndExplicitRolesA267(t *testing.T) {
	root := t.TempDir()
	good := DynamicSecretProviderConfig{
		TenantID: "57500000-0000-4000-8000-000000000001", ID: "directory", Type: "ldap", DirectoryMode: "active_directory",
		Addr: "directory.example:636", BindDN: "CN=rotation,OU=operators,DC=example,DC=test", PasswordRef: "file:" + filepath.Join(root, "rotation"),
		UsersDN: "OU=services,DC=example,DC=test", AllowedRoles: []string{"directory/service"}, RoleBindings: map[string]string{"directory/service": "CN=service,OU=services,DC=example,DC=test"}, AllowStaticRotation: true, MaxTTL: "1h",
		ADReconcile: &ADReconcileConfig{BindDN: "CN=reconcile,OU=operators,DC=example,DC=test", PasswordRef: "file:" + filepath.Join(root, "reconcile"), SID: "S-1-5-21-1-2-3-1002", GUID: strings.Repeat("a", 32), AllowedRoles: []string{"directory/service"}},
	}
	check := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*DynamicSecretProviderConfig){
		"non AD":                  func(c *DynamicSecretProviderConfig) { c.DirectoryMode = "" },
		"other backend":           func(c *DynamicSecretProviderConfig) { c.Type = "postgresql" },
		"same rotation principal": func(c *DynamicSecretProviderConfig) { c.ADReconcile.BindDN = c.BindDN },
		"escaped rotation principal": func(c *DynamicSecretProviderConfig) {
			c.ADReconcile.BindDN = `CN=\72otation,OU=operators,DC=example,DC=test`
		},
		"target principal":       func(c *DynamicSecretProviderConfig) { c.ADReconcile.BindDN = c.RoleBindings["directory/service"] },
		"missing credential ref": func(c *DynamicSecretProviderConfig) { c.ADReconcile.PasswordRef = "" },
		"same credential ref":    func(c *DynamicSecretProviderConfig) { c.ADReconcile.PasswordRef = c.PasswordRef },
		"credential value":       func(c *DynamicSecretProviderConfig) { c.ADReconcile.PasswordRef = "not-a-protected-reference" },
		"missing SID":            func(c *DynamicSecretProviderConfig) { c.ADReconcile.SID = "" },
		"malformed SID":          func(c *DynamicSecretProviderConfig) { c.ADReconcile.SID = "S-1-5-invented" },
		"missing GUID":           func(c *DynamicSecretProviderConfig) { c.ADReconcile.GUID = "" },
		"malformed GUID":         func(c *DynamicSecretProviderConfig) { c.ADReconcile.GUID = strings.Repeat("z", 32) },
		"no roles":               func(c *DynamicSecretProviderConfig) { c.ADReconcile.AllowedRoles = nil },
		"unknown role":           func(c *DynamicSecretProviderConfig) { c.ADReconcile.AllowedRoles = []string{"directory/other"} },
		"duplicate role": func(c *DynamicSecretProviderConfig) {
			c.ADReconcile.AllowedRoles = []string{"directory/service", "directory/service"}
		},
		"two user role": func(c *DynamicSecretProviderConfig) {
			c.RotationAccounts = map[string][]string{"directory/service": {c.RoleBindings["directory/service"], "CN=second,OU=services,DC=example,DC=test"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			profile := *good.ADReconcile
			profile.AllowedRoles = append([]string(nil), good.ADReconcile.AllowedRoles...)
			bad.ADReconcile = &profile
			change(&bad)
			if check(bad) == nil {
				t.Fatal("unsafe reconcile authority accepted")
			}
		})
	}
	ordinary := good
	ordinary.ADReconcile = nil
	if err := check(ordinary); err != nil {
		t.Fatal("optional reconcile profile changed ordinary AD configuration", err)
	}
}
