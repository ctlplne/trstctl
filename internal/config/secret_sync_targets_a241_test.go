// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A241: a hosted target takes its binding in the type's grammar and a token
// reference; a self-hosted type also needs its endpoint, and only types that
// authenticate with a user take username. binding and username belong to
// hosted types only.
func TestSecretSyncTargetsHostedA241(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	hosted := func(typ, binding string) SecretSyncTargetConfig {
		return SecretSyncTargetConfig{TenantID: tenant, ID: "t-" + typ, Type: typ, Binding: binding, TokenRef: "secret://integrations/" + typ}
	}
	for _, target := range []SecretSyncTargetConfig{
		hosted("heroku", "payments-api"),
		hosted("render", "srv-abc123def456"),
		hosted("railway", "project 11111111-2222-4333-8444-555555555555 environment 66666666-7777-4888-8999-aaaaaaaaaaaa"),
		hosted("fly", "payments"),
		hosted("digitalocean-app-platform", "app 0f0e0d0c-0b0a-4908-8706-050403020100 component web"),
		hosted("northflank", "project payments secret-group runtime"),
		hosted("qovery", "application aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
		hosted("cloud66", "stack-uid-12345"),
		hosted("laravel-forge", "org acme server 101 site 202"),
	} {
		if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{target}}, true); err != nil {
			t.Fatalf("%s: %v", target.Type, err)
		}
	}
	for _, c := range []struct {
		target SecretSyncTargetConfig
		want   string
	}{
		{hosted("heroku", ""), "binding for heroku"},
		{hosted("heroku", "Payments_API"), "a Heroku app name or ID"},
		{hosted("railway", "project 11111111-2222-4333-8444-555555555555"), "environment is required"},
		{hosted("railway", "project x environment y"), "must be a UUID"},
		{hosted("qovery", "service aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), "a scope (application"},
		{hosted("laravel-forge", "org acme server web site 202"), "server must be a server ID"},
		{func() SecretSyncTargetConfig { c := hosted("fly", "payments"); c.TokenRef = ""; return c }(), "token_ref"},
		{func() SecretSyncTargetConfig { c := hosted("fly", "payments"); c.Username = "ops"; return c }(), "username is not used by fly"},
		{func() SecretSyncTargetConfig {
			return SecretSyncTargetConfig{TenantID: tenant, ID: "gh", Type: "github-actions", Owner: "o", Repo: "r", TokenRef: "secret://gh", Binding: "x"}
		}(), "binding and username are for hosted targets"},
	} {
		err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{c.target}}, true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s %q: err = %v, want %q", c.target.Type, c.target.Binding, err, c.want)
		}
	}
}
