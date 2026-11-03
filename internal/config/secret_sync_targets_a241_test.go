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
		hosted("circleci", "project gh/acme/payments"),
		hosted("circleci", "context 0f0e0d0c-0b0a-4908-8706-050403020100"),
		hosted("travis-ci", "acme/payments"),
		hosted("bitbucket", "workspace acme repository payments"),
		func() SecretSyncTargetConfig {
			c := hosted("teamcity", "project Payments")
			c.Endpoint = "https://teamcity.example.test"
			return c
		}(),
		func() SecretSyncTargetConfig {
			c := hosted("spacelift", "context payments-env")
			c.Endpoint, c.Username = "https://acme.app.spacelift.io/graphql", "01A241KEYID"
			return c
		}(),
		hosted("humanitec", "org acme app payments"),
		func() SecretSyncTargetConfig {
			c := hosted("rundeck", "folder keys/project/payments")
			c.Endpoint = "https://rundeck.example.test"
			return c
		}(),
		hosted("checkly", "account cccccccc-dddd-4eee-8fff-000000000000"),
		hosted("windmill", "workspace payments"),
		func() SecretSyncTargetConfig {
			c := hosted("zabbix", "host 10084")
			c.Endpoint = "https://zabbix.example.test/api_jsonrpc.php"
			return c
		}(),
		func() SecretSyncTargetConfig {
			c := hosted("portainer", "stack 7 environment 3")
			c.Endpoint = "https://portainer.example.test:9443"
			return c
		}(),
		hosted("devin", "org org-acme"),
		hosted("daytona", ""),
		hosted("ona", "project eeeeeeee-ffff-4000-8111-222222222222"),
		hosted("trigger-dev", "project proj_a241payments env staging"),
		hosted("cloudflare-workers", "account 0123456789abcdef0123456789abcdef script payments-worker"),
		hosted("cloudflare-pages", "account 0123456789abcdef0123456789abcdef project payments-site environment preview"),
		hosted("cloudflare-secrets-store", "account 0123456789abcdef0123456789abcdef store fedcba9876543210fedcba9876543210"),
		func() SecretSyncTargetConfig {
			c := hosted("azure-app-configuration", "label prod")
			c.Endpoint, c.Username = "https://payments.azconfig.io", "a241-credential"
			return c
		}(),
		func() SecretSyncTargetConfig {
			c := hosted("oci-vault", "compartment ocid1.compartment.oc1..aaaaaaaacompart vault ocid1.vault.oc1.iad.aaaaaaaavault key ocid1.key.oc1.iad.aaaaaaaakey00001")
			c.Endpoint, c.Username = "https://vaults.us-ashburn-1.oci.oraclecloud.com/20180608", "ocid1.tenancy.oc1..x/ocid1.user.oc1..y/aa:bb"
			return c
		}(),
		func() SecretSyncTargetConfig {
			c := hosted("ovh-secret-manager", "okms aaaaaaaa-1111-4222-8333-444444444444")
			c.Endpoint = "https://eu-west-rbx.okms.ovh.net"
			return c
		}(),
		func() SecretSyncTargetConfig {
			c := hosted("databricks-secrets", "scope payments")
			c.Endpoint = "https://dbc-a241.cloud.databricks.com"
			return c
		}(),
		hosted("supabase-secrets", "project abcdefghijklmnopqrst"),
		func() SecretSyncTargetConfig {
			c := hosted("camunda", "cluster bbbbbbbb-2222-4333-8444-555555555555")
			c.Username = "a241-client"
			return c
		}(),
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
		{hosted("teamcity", "project Payments"), "teamcity has no fixed API base: endpoint is required"},
		{func() SecretSyncTargetConfig {
			c := hosted("spacelift", "context payments-env")
			c.Endpoint = "https://acme.app.spacelift.io/graphql"
			return c
		}(), "username is required for spacelift"},
		{hosted("circleci", "project acme/payments"), "project must be a project slug"},
		{hosted("rundeck", "folder project/payments"), "a Key Storage folder under keys/"},
		{hosted("zabbix", "global"), "zabbix has no fixed API base: endpoint is required"},
		{hosted("trigger-dev", "project proj_a241payments env preview"), "env must be dev, staging or prod"},
		{hosted("ona", "team eeeeeeee-ffff-4000-8111-222222222222"), "organization, project or user"},
		{hosted("cloudflare-pages", "account 0123456789abcdef0123456789abcdef project payments-site environment staging"), "production or preview"},
		{hosted("oci-vault", "compartment c vault v key k"), "compartment must be a compartment OCID"},
		{hosted("supabase-secrets", "project ABC"), "a 20-letter project ref"},
		{hosted("databricks-secrets", "scope payments"), "databricks-secrets has no fixed API base: endpoint is required"},
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
