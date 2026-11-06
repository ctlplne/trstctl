// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

func TestADReviewedAccountsAreFrozenAndWarnOfInPlaceRotation(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{Type: "ldap", DirectoryMode: "active_directory", AllowStaticRotation: true, RoleBindings: map[string]string{"single": "CN=single,OU=services,DC=example,DC=test", "pair": "CN=a,OU=services,DC=example,DC=test"}, RotationAccounts: map[string][]string{"pair": {"CN=a,OU=services,DC=example,DC=test", "CN=b,OU=services,DC=example,DC=test"}}}
	p := newConfiguredDynamicProvider(cfg, map[string]bool{"single": true, "pair": true}, time.Hour, integrationCredentialResolver{}, nil).(*configuredDynamicProvider)
	cfg.RoleBindings["single"] = "CN=foreign,OU=services,DC=example,DC=test"
	cfg.RotationAccounts["pair"][0] = "CN=foreign,OU=services,DC=example,DC=test"
	if p.cfg.RoleBindings["single"] == cfg.RoleBindings["single"] || p.cfg.RotationAccounts["pair"][0] == cfg.RotationAccounts["pair"][0] {
		t.Fatal("reviewed AD authority changed through caller aliases")
	}
	if p.RotationPhase("single") != dynsecret.RotationSinglePhase || p.RotationPhase("pair") != dynsecret.RotationTwoPhase {
		t.Fatal("wrong AD interruption warning")
	}
	p.open = func(context.Context) (requestDynamicBackend, func(), error) {
		t.Fatal("unsupported dynamic issuance reached an external provider")
		return nil, nil, nil
	}
	if _, err := p.Generate(context.Background(), dynsecret.GenerateRequest{Role: "single", TTL: time.Minute}); err == nil {
		t.Fatal("dynamic AD user issuance invented")
	}
}
