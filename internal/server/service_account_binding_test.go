// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

func TestADStaticBindingSurvivesRestartButRefusesConfigChangeA267(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{ID: "directory", Type: "ldap", DirectoryMode: "active_directory", Addr: "directory.example:636", AllowedRoles: []string{"service"}, RoleBindings: map[string]string{"service": "CN=service,OU=services,DC=example,DC=test"}, AllowStaticRotation: true}
	provider := func(cfg config.DynamicSecretProviderConfig) dynsecret.Provider {
		return newConfiguredDynamicProvider(cfg, map[string]bool{"service": true}, time.Hour, integrationCredentialResolver{}, nil)
	}
	first := provider(cfg).(dynsecret.PreparedStaticRotationProvider).StaticRotationBinding("service")
	second := provider(cfg).(dynsecret.PreparedStaticRotationProvider).StaticRotationBinding("service")
	if len(first) != 64 || first != second {
		t.Fatal("native authority changed only because the process restarted")
	}
	changed := cfg
	changed.Addr = "different.example:636"
	if first == provider(changed).(dynsecret.PreparedStaticRotationProvider).StaticRotationBinding("service") {
		t.Fatal("changed native endpoint retained the old authority")
	}
	changed = cfg
	changed.DirectoryMode = ""
	if _, ok := provider(changed).(dynsecret.PreparedStaticRotationProvider); ok {
		t.Fatal("generic LDAP accidentally advertised AD native preparation")
	}
}
