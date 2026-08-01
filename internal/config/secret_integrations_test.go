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
			{TenantID: tenant, ID: "tfc-opentofu", Type: "terraform-cloud-opentofu", Endpoint: "https://app.terraform.io", WorkspaceID: "ws-production", VariableCategory: "env", TokenRef: ref},
			{TenantID: tenant, ID: "vault-kv", Type: "vault-kv-v2", Endpoint: "https://vault.example.test", Mount: "team-secrets", PathPrefix: "apps/production", Field: "value", VaultNamespace: "platform/team-a", TokenRef: ref},
		},
	}
	if err := ValidateSecretIntegrations(cfg, true); err != nil {
		t.Fatalf("all built-ins should validate: %v", err)
	}
}

func TestValidateSecretIntegrationsAWSFederatedIsExplicitAndRejectsStaticFallback(t *testing.T) {
	base := SecretSyncTargetConfig{
		TenantID: "11111111-1111-1111-1111-111111111111",
		ID:       "aws-federated", Type: "aws-secrets-manager",
		Endpoint: "https://secretsmanager.us-east-1.amazonaws.com",
		Region:   "us-east-1", AWSWorkloadIdentity: true,
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{base}}, true); err != nil {
		t.Fatalf("explicit AWS workload identity target rejected: %v", err)
	}
	withStatic := base
	withStatic.AccessKeyID = "AKID"
	withStatic.SecretAccessRef = "file:/run/secrets/aws"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{withStatic}}, true); err == nil ||
		!strings.Contains(err.Error(), "forbids static") {
		t.Fatalf("AWS workload identity with static fallback error = %v", err)
	}
	implicit := base
	implicit.AWSWorkloadIdentity = false
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{implicit}}, true); err == nil ||
		!strings.Contains(err.Error(), "access_key_id") {
		t.Fatalf("implicit AWS workload identity target error = %v", err)
	}
}

func TestValidateSecretIntegrationsGCPFederatedIsExplicitAndRejectsStaticFallback(t *testing.T) {
	base := SecretSyncTargetConfig{
		TenantID: "11111111-1111-1111-1111-111111111111",
		ID:       "gcp-federated", Type: "gcp-secret-manager",
		Endpoint: "https://secretmanager.googleapis.com",
		Project:  "payments-production", GCPWorkloadIdentity: true,
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{base}}, true); err != nil {
		t.Fatalf("explicit GCP workload identity target rejected: %v", err)
	}
	withStatic := base
	withStatic.TokenRef = "file:/run/secrets/gcp-token"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{withStatic}}, true); err == nil ||
		!strings.Contains(err.Error(), "forbids static token_ref") {
		t.Fatalf("GCP workload identity with static fallback error = %v", err)
	}
	implicit := base
	implicit.GCPWorkloadIdentity = false
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{implicit}}, true); err == nil ||
		!strings.Contains(err.Error(), "token_ref") {
		t.Fatalf("implicit GCP workload identity target error = %v", err)
	}
}

func TestValidateSecretIntegrationsAzureFederatedIsExplicitAndRejectsStaticFallback(t *testing.T) {
	base := SecretSyncTargetConfig{
		TenantID: "11111111-1111-1111-1111-111111111111",
		ID:       "azure-federated", Type: "azure-key-vault",
		Endpoint: "https://payments.vault.azure.net", AzureWorkloadIdentity: true,
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{base}}, true); err != nil {
		t.Fatalf("explicit Azure workload identity target rejected: %v", err)
	}
	withStatic := base
	withStatic.TokenRef = "file:/run/secrets/azure-token"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{withStatic}}, true); err == nil ||
		!strings.Contains(err.Error(), "forbids static token_ref") {
		t.Fatalf("Azure workload identity with static fallback error = %v", err)
	}
	implicit := base
	implicit.AzureWorkloadIdentity = false
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{implicit}}, true); err == nil ||
		!strings.Contains(err.Error(), "token_ref") {
		t.Fatalf("implicit Azure workload identity target error = %v", err)
	}
	wrongProvider := base
	wrongProvider.Type = "gcp-secret-manager"
	wrongProvider.Project = "payments-production"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{wrongProvider}}, true); err == nil ||
		!strings.Contains(err.Error(), "only valid for azure-key-vault") {
		t.Fatalf("Azure workload identity on a non-Azure target error = %v", err)
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
			cfg: SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{{TenantID: tenant, ID: "k8s", Type: "kubernetes", Endpoint: "https://example.test", Namespace: "default", BearerTokenRef: "secret://k8s-token", AllowedRoles: []string{"read"}}}}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		{
			name: "unsafe private endpoint policy", on: true, want: "requires private_egress_cidrs",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "gcp", Type: "gcp-secret-manager", Endpoint: "http://127.0.0.1:8080", Project: "p", TokenRef: "secret://gcp-token", AllowPrivate: true}}}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		{
			name: "Terraform invalid category", on: true, want: "variable_category must be terraform or env",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "tfc", Type: "terraform-cloud-opentofu", Endpoint: "https://app.terraform.io", WorkspaceID: "ws-production", VariableCategory: "secret", TokenRef: "secret://tfc-token"}}}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		{
			name: "Terraform environment HCL", on: true, want: "hcl=true is valid only for terraform variables",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "tfc", Type: "terraform-cloud-opentofu", Endpoint: "https://app.terraform.io", WorkspaceID: "ws-production", VariableCategory: "env", HCL: true, TokenRef: "secret://tfc-token"}}}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		{
			name: "Vault traversal path", on: true, want: "path_prefix must not contain dot path components",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "vault", Type: "vault-kv-v2", Endpoint: "https://vault.example.test", Mount: "secret", PathPrefix: "apps/../admin", TokenRef: "secret://vault-token"}}},
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
