// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestAzureGatewayConfigurationRejectsUnreviewableOAuthAuthority(t *testing.T) {
	file := filepath.Join(t.TempDir(), "issuer")
	if err := os.WriteFile(file, []byte("owned-example-authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := DynamicSecretProviderConfig{TenantID: "54100000-0000-4000-8000-000000000001", ID: "azure-reader", Type: "azure-entra", Endpoint: "https://graph.microsoft.com", ApplicationObject: "owned-object", ApplicationClient: "owned-client", AzureTenant: "owned-tenant", BearerTokenRef: "file:" + file, AllowedRoles: []string{"reader"}, MaxTTL: "1h", Gateway: &DynamicSecretGatewayConfig{Endpoint: "https://graph.microsoft.com", TokenEndpoint: (&url.URL{Scheme: "https", Host: "login.microsoftonline.com", Path: "/owned-tenant/oauth2/v2.0/token"}).String(), Scopes: []string{"https://graph.microsoft.com/.default"}}}
	validate := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := validate(base); err != nil {
		t.Fatal(err)
	}
	for i, change := range []func(*DynamicSecretProviderConfig){func(c *DynamicSecretProviderConfig) { c.Gateway.Service = "s3" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Region = "us-east-1" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Scopes = nil }, func(c *DynamicSecretProviderConfig) { c.Gateway.Scopes = append(c.Gateway.Scopes, c.Gateway.Scopes[0]) }, func(c *DynamicSecretProviderConfig) {
		c.Gateway.Scopes = []string{"https://www.googleapis.com/auth/a https://www.googleapis.com/auth/b"}
	}, func(c *DynamicSecretProviderConfig) {
		c.Gateway.Scopes = []string{"https://user:password@example/scope"}
	}, func(c *DynamicSecretProviderConfig) {
		c.Gateway.TokenEndpoint = "https://oauth.example/token?audience=foreign"
	}, func(c *DynamicSecretProviderConfig) {
		c.Gateway.TokenEndpoint = "https://user:password@oauth.example/token"
	}, func(c *DynamicSecretProviderConfig) { c.Gateway.TokenEndpoint = "http://oauth.example/token" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "https://storage.example/path" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "https://user:password@storage.example" }, func(c *DynamicSecretProviderConfig) { c.Type = "aws-sts" }, func(c *DynamicSecretProviderConfig) { c.AzureTenant = "common" }, func(c *DynamicSecretProviderConfig) { c.AzureTenant = "Common" }, func(c *DynamicSecretProviderConfig) { c.AzureTenant = ".." }, func(c *DynamicSecretProviderConfig) { c.AzureTenant = "owned@foreign" }, func(c *DynamicSecretProviderConfig) { c.AzureTenant = "other-tenant" }, func(c *DynamicSecretProviderConfig) { c.AuthorityHost = "https://foreign.example" }, func(c *DynamicSecretProviderConfig) {
		c.Gateway.Scopes = []string{"https://graph.microsoft.com/User.Read"}
	}} {
		c := base
		g := *base.Gateway
		g.Scopes = append([]string(nil), g.Scopes...)
		c.Gateway = &g
		change(&c)
		if validate(c) == nil {
			t.Fatalf("unsafe OAuth binding accepted case %d", i)
		}
	}
}
