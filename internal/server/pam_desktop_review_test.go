// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/accessdesktop"
	"trstctl.com/trstctl/internal/config"
)

func TestDesktopReviewedRouteCannotChangeThroughConfigurationAliases(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{Type: "unix", AllowStaticRotation: true, Desktop: &accessdesktop.Binding{Address: "host.example:3389", CertificateSHA256: strings.Repeat("ab", 32), Width: 800, Height: 600}}
	provider := newConfiguredDynamicProvider(cfg, nil, time.Minute, integrationCredentialResolver{}, nil).(*configuredDynamicProvider)
	cfg.Desktop.Address = "foreign.example:3389"
	a, err := provider.DynamicSecretGatewayDesktop("desktop/account")
	if err != nil || a.Address != "host.example:3389" {
		t.Fatal("reviewed desktop route changed through caller alias")
	}
	a.Address = "another.example:3389"
	b, err := provider.DynamicSecretGatewayDesktop("desktop/account")
	if err != nil || b.Address != "host.example:3389" {
		t.Fatal("returned route mutated the reviewed authority")
	}
}

func TestADDesktopBindingFreezesOnlyTheRequestedRole(t *testing.T) {
	const first = "CN=first,OU=services,DC=example,DC=test"
	const second = "CN=second,OU=services,DC=example,DC=test"
	cfg := config.DynamicSecretProviderConfig{Type: "ldap", DirectoryMode: "active_directory", AllowStaticRotation: true, RoleBindings: map[string]string{"first": first, "second": second}, ADLogonNames: map[string]string{first: "first", second: "second"}, Desktop: &accessdesktop.Binding{Address: "desktop.example:3389", CertificateSHA256: strings.Repeat("ab", 32), Width: 800, Height: 600}}
	p := configuredADProvider(t, newConfiguredDynamicProvider(cfg, map[string]bool{"first": true, "second": true}, time.Minute, integrationCredentialResolver{}, nil))
	cfg.ADLogonNames[first] = "foreign"
	a, err := p.DynamicSecretGatewayDesktop("first")
	if err != nil || len(a.Accounts) != 1 || a.Accounts[0].Reference != first || a.Accounts[0].Username != "first" {
		t.Fatal("wrong reviewed AD role binding")
	}
	if a.PermitsAccount(second, "second") {
		t.Fatal("another role's account entered this session")
	}
	a.Accounts[0].Username = "foreign"
	b, err := p.DynamicSecretGatewayDesktop("first")
	if err != nil || b.Accounts[0].Username != "first" {
		t.Fatal("returned desktop identity mutated its review source")
	}
	if _, err = p.DynamicSecretGatewayDesktop("foreign"); err == nil {
		t.Fatal("unknown desktop role allowed")
	}
}
