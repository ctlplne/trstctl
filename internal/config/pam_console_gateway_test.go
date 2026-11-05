// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"os"
	"path/filepath"
	"testing"
	"trstctl.com/trstctl/internal/accessconsole"
)

func TestConsoleProviderConfigurationRequiresSTSAndExplicitNativeDestinations(t *testing.T) {
	file := filepath.Join(t.TempDir(), "issuer")
	if err := os.WriteFile(file, []byte("owned-issuer-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := DynamicSecretProviderConfig{TenantID: "54200000-0000-4000-8000-000000000001", ID: "console-reader", Type: "aws-sts", Endpoint: "https://sts.us-east-1.amazonaws.com", Region: "us-east-1", AccessKeyID: "test", SecretAccessRef: "file:" + file, AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "arn:aws:iam::123456789012:role/reader"}, MaxTTL: "1h", Console: &accessconsole.Binding{FederationEndpoint: "https://signin.aws.amazon.com/federation", Destination: "https://console.aws.amazon.com/"}}
	validate := func(c DynamicSecretProviderConfig) error {
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := validate(base); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DynamicSecretProviderConfig){func(c *DynamicSecretProviderConfig) { c.Type = "aws-iam" }, func(c *DynamicSecretProviderConfig) { c.Console.Destination = "https://foreign.example/" }, func(c *DynamicSecretProviderConfig) {
		c.Console.FederationEndpoint = "https://signin.aws.amazon.com/federation?Session=foreign"
	}, func(c *DynamicSecretProviderConfig) {
		c.Console.FederationEndpoint = "http://127.0.0.1:1234/federation"
	}} {
		cfg := base
		b := *base.Console
		cfg.Console = &b
		change(&cfg)
		if validate(cfg) == nil {
			t.Fatal("invalid console attachment accepted")
		}
	}
}
