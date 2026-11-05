// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestGCPGatewayConfigurationRejectsUnreviewableOAuthAuthority(t *testing.T) {
	file := filepath.Join(t.TempDir(), "issuer")
	if err := os.WriteFile(file, []byte("owned-example-authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := DynamicSecretProviderConfig{TenantID: "54000000-0000-4000-8000-000000000001", ID: "gcp-reader", Type: "gcp-iam", Endpoint: "https://iam.googleapis.com", Project: "p", ServiceAccount: "reader@p.iam.gserviceaccount.com", BearerTokenRef: "file:" + file, AllowedRoles: []string{"reader"}, MaxTTL: "1h", Gateway: &DynamicSecretGatewayConfig{Endpoint: "https://storage.googleapis.com", TokenEndpoint: (&url.URL{Scheme: "https", Host: "oauth2.googleapis.com", Path: "/token"}).String(), Scopes: []string{"https://www.googleapis.com/auth/devstorage.read_only"}}}
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
	}, func(c *DynamicSecretProviderConfig) { c.Gateway.TokenEndpoint = "http://oauth.example/token" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "https://storage.example/path" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "https://user:password@storage.example" }, func(c *DynamicSecretProviderConfig) { c.Type = "azure-entra" }} {
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
