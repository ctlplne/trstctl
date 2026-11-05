// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAWSGatewayConfigurationPinsAnExplicitOriginAndScope(t *testing.T) {
	issuerFile := filepath.Join(t.TempDir(), "issuer-material")
	if err := os.WriteFile(issuerFile, []byte("owned-example-authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuerRef := "file:" + issuerFile
	base := DynamicSecretProviderConfig{TenantID: "53900000-0000-4000-8000-000000000001", ID: "aws-reader", Type: "aws-sts", Endpoint: "https://sts.us-east-1.amazonaws.com", Region: "us-east-1", AccessKeyID: "test", SecretAccessRef: issuerRef, AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "arn:aws:iam::123456789012:role/reader"}, MaxTTL: "1h", Gateway: &DynamicSecretGatewayConfig{Endpoint: "https://s3.us-east-1.amazonaws.com", Service: "s3", Region: "us-east-1"}}
	validate := func(cfg DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{cfg}}, true)
	}
	if err := validate(base); err != nil {
		t.Fatal(err)
	}
	for i, change := range []func(*DynamicSecretProviderConfig){func(c *DynamicSecretProviderConfig) { c.Gateway.Service = "iam" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Region = "us-east-1;id" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "https://s3.example/?credential=bad" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "https://s3.example/client-route" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "https://user:password@s3.example" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "http://s3.example" }, func(c *DynamicSecretProviderConfig) { c.Gateway.Endpoint = "http://127.0.0.1:8123" }, func(c *DynamicSecretProviderConfig) { c.Type = "aws-iam" }} {
		cfg := base
		gateway := *base.Gateway
		cfg.Gateway = &gateway
		change(&cfg)
		if err := validate(cfg); err == nil {
			t.Fatalf("unreviewable gateway origin/scope accepted in case %d", i)
		}
	}
}
