// SPDX-License-Identifier: MPL-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateSecretIntegrationsAcceptsEveryBuiltIn(t *testing.T) {
	const (
		tenant = "11111111-1111-1111-1111-111111111111"
		ref    = "file:/var/lib/trstctl/fixtures/credential"
	)
	role := []string{"reader"}
	cfg := SecretIntegrationsConfig{
		DynamicProviders: []DynamicSecretProviderConfig{
			{TenantID: tenant, ID: "pg", Type: "postgresql", AdminDSNRef: ref, AllowedRoles: role},
			{TenantID: tenant, ID: "mysql", Type: "mysql", AdminDSNRef: ref, Database: "app", Addr: "mysql.internal:3306", AllowedRoles: role},
			{TenantID: tenant, ID: "mongo", Type: "mongodb", AdminDSNRef: ref, Database: "app", AllowedRoles: role},
			{TenantID: tenant, ID: "aws", Type: "aws-iam", Endpoint: "https://iam.example.test", Region: "us-east-1", AccessKeyID: "AKID", SecretAccessRef: ref, AllowedRoles: role, RoleBindings: map[string]string{"reader": "arn:aws:iam::aws:policy/ReadOnlyAccess"}},
			{TenantID: tenant, ID: "gcp", Type: "gcp-iam", Endpoint: "https://iam.example.test", Project: "project", ServiceAccount: "issuer@example.test", BearerTokenRef: ref, AllowedRoles: role},
			{TenantID: tenant, ID: "azure", Type: "azure-entra", Endpoint: "https://graph.example.test", ApplicationObject: "object", ApplicationClient: "client", AzureTenant: "tenant", BearerTokenRef: ref, AllowedRoles: role},
			{TenantID: tenant, ID: "k8s", Type: "kubernetes", Endpoint: "https://kubernetes.example.test", Namespace: "default", BearerTokenRef: ref, AllowedRoles: role, RoleBindings: map[string]string{"reader": "Role/secret-reader"}},
			{TenantID: tenant, ID: "redis", Type: "redis", Addr: "redis.internal:6379", PasswordRef: ref, AllowedRoles: role},
		},
		SyncTargets: []SecretSyncTargetConfig{
			{TenantID: tenant, ID: "aws-sm", Type: "aws-secrets-manager", Endpoint: "https://secretsmanager.example.test", Region: "us-east-1", AccessKeyID: "AKID", SecretAccessRef: ref},
			{TenantID: tenant, ID: "gcp-sm", Type: "gcp-secret-manager", Endpoint: "https://secretmanager.example.test", Project: "project", TokenRef: ref},
			{TenantID: tenant, ID: "azure-kv", Type: "azure-key-vault", Endpoint: "https://vault.example.test", TokenRef: ref},
			{TenantID: tenant, ID: "github", Type: "github-actions", Endpoint: "https://api.github.example.test", Owner: "owner", Repo: "repo", TokenRef: ref},
			{TenantID: tenant, ID: "gitlab", Type: "gitlab-ci", Endpoint: "https://gitlab.example.test", ProjectID: "42", TokenRef: ref},
			{TenantID: tenant, ID: "vercel", Type: "vercel", Endpoint: "https://vercel.example.test", ProjectID: "project", TokenRef: ref},
			{TenantID: tenant, ID: "generic", Type: "generic-ci-json", Endpoint: "https://ci.example.test", Provider: "build", TokenRef: ref},
			{TenantID: tenant, ID: "k8s-secret", Type: "kubernetes-secrets", Endpoint: "https://kubernetes.example.test", Namespace: "default", TokenRef: ref},
		},
	}
	if err := ValidateSecretIntegrations(cfg, true); err != nil {
		t.Fatalf("all built-ins should validate: %v", err)
	}
}

func TestValidateSecretIntegrationsFailsClosed(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	tests := []struct {
		name string
		cfg  SecretIntegrationsConfig
		on   bool
		want string
	}{
		{
			name: "API disabled", on: false, want: "require secrets.enable_api=true",
			cfg: SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{{TenantID: tenant, ID: "redis", Type: "redis", Addr: "redis:6379", AllowedRoles: []string{"read"}}}},
		},
		{
			name: "inline credential", on: true, want: "must use file:",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "gcp", Type: "gcp-secret-manager", Endpoint: "https://example.test", Project: "p", TokenRef: "plaintext-token"}}},
		},
		{
			name: "relative credential file", on: true, want: "absolute path",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "gcp", Type: "gcp-secret-manager", Endpoint: "https://example.test", Project: "p", TokenRef: "file:token"}}},
		},
		{
			name: "tenant duplicate", on: true, want: "duplicates tenant/id",
			cfg: SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{
				{TenantID: tenant, ID: "redis", Type: "redis", Addr: "one:6379", AllowedRoles: []string{"read"}},
				{TenantID: tenant, ID: "redis", Type: "redis", Addr: "two:6379", AllowedRoles: []string{"read"}},
			}},
		},
		{
			name: "unbound Kubernetes role", on: true, want: "role_bindings",
			cfg: SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{{TenantID: tenant, ID: "k8s", Type: "kubernetes", Endpoint: "https://example.test", Namespace: "default", BearerTokenRef: "secret://k8s-token", AllowedRoles: []string{"read"}}}},
		},
		{
			name: "unsafe private endpoint policy", on: true, want: "requires private_egress_cidrs",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "gcp", Type: "gcp-secret-manager", Endpoint: "http://127.0.0.1:8080", Project: "p", TokenRef: "secret://gcp-token", AllowPrivate: true}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretIntegrations(tt.cfg, tt.on)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateSecretIntegrationsRequiresHTTPSExceptExplicitLoopback(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	base := func(endpoint string) SecretSyncTargetConfig {
		return SecretSyncTargetConfig{
			TenantID: tenant, ID: "generic", Type: "generic-ci-json",
			Endpoint: endpoint, Provider: "build",
		}
	}
	tests := []struct {
		name string
		edit func(*SecretSyncTargetConfig)
		ok   bool
	}{
		{name: "HTTPS production", edit: func(c *SecretSyncTargetConfig) { c.Endpoint = "https://sync.example.test" }, ok: true},
		{name: "public HTTP with insecure opt in", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://198.51.100.10:8080"
			c.AllowInsecureLoopback = true
		}},
		{name: "private HTTP with both egress knobs", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://10.1.2.3:8080"
			c.AllowPrivate = true
			c.PrivateEgressCIDRs = []string{"10.0.0.0/8"}
			c.AllowInsecureLoopback = true
		}},
		{name: "allow private alone cannot enable loopback HTTP", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://127.0.0.1:8080"
			c.AllowPrivate = true
			c.PrivateEgressCIDRs = []string{"127.0.0.0/8"}
		}},
		{name: "loopback HTTP explicit opt in", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://127.0.0.1:8080"
			c.AllowInsecureLoopback = true
		}, ok: true},
		{name: "localhost HTTP explicit opt in", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://localhost:8080"
			c.AllowInsecureLoopback = true
		}, ok: true},
		{name: "unused insecure opt in", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "https://sync.example.test"
			c.AllowInsecureLoopback = true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := base("https://sync.example.test")
			tt.edit(&entry)
			err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{entry}}, true)
			if (err == nil) != tt.ok {
				t.Fatalf("ValidateSecretIntegrations() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}
