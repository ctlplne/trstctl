// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/netsec"
)

func TestSecretIntegrationFactoriesBuildAllTenantBoundRegistrations(t *testing.T) {
	const (
		tenantA = "11111111-1111-1111-1111-111111111111"
		tenantB = "22222222-2222-2222-2222-222222222222"
		ref     = "file:/var/lib/trstctl/test/credential"
	)
	role := []string{"reader"}
	dynamic := []config.DynamicSecretProviderConfig{
		{TenantID: tenantA, ID: "pg", Type: "postgresql", AdminDSNRef: ref, AllowedRoles: role},
		{TenantID: tenantA, ID: "mysql", Type: "mysql", AdminDSNRef: ref, Database: "app", Addr: "mysql.internal:3306", AllowedRoles: role},
		{TenantID: tenantA, ID: "mongo", Type: "mongodb", AdminDSNRef: ref, Database: "app", AllowedRoles: role},
		{TenantID: tenantA, ID: "aws", Type: "aws-iam", Endpoint: "https://iam.example.test", Region: "us-east-1", AccessKeyID: "AKID", SecretAccessRef: ref, AllowedRoles: role, RoleBindings: map[string]string{"reader": "arn:aws:iam::aws:policy/ReadOnlyAccess"}},
		{TenantID: tenantA, ID: "gcp", Type: "gcp-iam", Endpoint: "https://iam.example.test", Project: "p", ServiceAccount: "issuer@example.test", BearerTokenRef: ref, AllowedRoles: role},
		{TenantID: tenantA, ID: "azure", Type: "azure-entra", Endpoint: "https://graph.example.test", ApplicationObject: "object", ApplicationClient: "client", AzureTenant: "tenant", BearerTokenRef: ref, AllowedRoles: role},
		{TenantID: tenantA, ID: "k8s", Type: "kubernetes", Endpoint: "https://kubernetes.example.test", Namespace: "apps", BearerTokenRef: ref, AllowedRoles: role, RoleBindings: map[string]string{"reader": "Role/reader"}},
		{TenantID: tenantA, ID: "redis", Type: "redis", Addr: "redis.internal:6379", PasswordRef: ref, AllowedRoles: role},
		{TenantID: tenantB, ID: "redis-b", Type: "redis", Addr: "redis-b.internal:6379", AllowedRoles: role},
	}
	dynamicRegistry, err := dynamicSecretProvidersFromConfig(context.Background(), dynamic, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(dynamicRegistry.ForTenant(tenantA)); got != 8 {
		t.Fatalf("tenant A dynamic providers = %d, want 8", got)
	}
	if got := len(dynamicRegistry.ForTenant(tenantB)); got != 1 || dynamicRegistry.ForTenant(tenantB)[0].Name() != "redis-b" {
		t.Fatalf("tenant B dynamic providers = %#v", dynamicRegistry.ForTenant(tenantB))
	}
	if got := dynamicRegistry.ForTenant("33333333-3333-3333-3333-333333333333"); len(got) != 0 {
		t.Fatalf("unknown tenant received providers: %#v", got)
	}
	for _, provider := range dynamicRegistry.ForTenant(tenantA) {
		_, prepared := provider.(dynsecret.PreparedProvider)
		if want := provider.Name() == "gcp"; prepared != want {
			t.Errorf("provider %s prepared-provider=%v, want %v; only GCP has a durable local retry identity", provider.Name(), prepared, want)
		}
	}

	syncEntries := []config.SecretSyncTargetConfig{
		{TenantID: tenantA, ID: "aws-sm", Type: "aws-secrets-manager", Endpoint: "https://secretsmanager.example.test", Region: "us-east-1", AccessKeyID: "AKID", SecretAccessRef: ref},
		{TenantID: tenantA, ID: "gcp-sm", Type: "gcp-secret-manager", Endpoint: "https://secretmanager.example.test", Project: "p", TokenRef: ref},
		{TenantID: tenantA, ID: "azure-kv", Type: "azure-key-vault", Endpoint: "https://vault.example.test", TokenRef: ref},
		{TenantID: tenantA, ID: "github", Type: "github-actions", Endpoint: "https://github.example.test", Owner: "acme", Repo: "payments", TokenRef: ref},
		{TenantID: tenantA, ID: "gitlab", Type: "gitlab-ci", Endpoint: "https://gitlab.example.test", ProjectID: "42", TokenRef: ref},
		{TenantID: tenantA, ID: "vercel", Type: "vercel", Endpoint: "https://vercel.example.test", ProjectID: "payments", TokenRef: ref},
		{TenantID: tenantA, ID: "generic", Type: "generic-ci-json", Endpoint: "https://ci.example.test", Provider: "build", TokenRef: ref},
		{TenantID: tenantA, ID: "k8s-secret", Type: "kubernetes-secrets", Endpoint: "https://kubernetes.example.test", Namespace: "apps", TokenRef: ref},
		{TenantID: tenantB, ID: "generic-b", Type: "generic-ci-json", Endpoint: "https://ci-b.example.test", Provider: "build"},
	}
	syncRegistry, err := secretSyncTargetsFromConfig(context.Background(), syncEntries, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(syncRegistry.ForTenant(tenantA)); got != 8 {
		t.Fatalf("tenant A sync targets = %d, want 8", got)
	}
	if got := syncRegistry.ForTenant(tenantB); len(got) != 1 || got["generic-b"] == nil {
		t.Fatalf("tenant B sync targets = %#v", got)
	}
	if got := syncRegistry.ForTenant("33333333-3333-3333-3333-333333333333"); len(got) != 0 {
		t.Fatalf("unknown tenant received sync targets: %#v", got)
	}
}

func TestSecretIntegrationFactoriesRejectUnsafeHTTPAtStartup(t *testing.T) {
	tests := []config.SecretSyncTargetConfig{
		{
			TenantID: "11111111-1111-1111-1111-111111111111", ID: "public", Type: "generic-ci-json",
			Endpoint: "http://public.example.test", Provider: "build", AllowInsecureLoopback: true,
		},
		{
			TenantID: "11111111-1111-1111-1111-111111111111", ID: "private", Type: "generic-ci-json",
			Endpoint: "http://10.1.2.3:8080", Provider: "build", AllowPrivate: true,
			PrivateEgressCIDRs: []string{"10.0.0.0/8"}, AllowInsecureLoopback: true,
		},
		{
			TenantID: "11111111-1111-1111-1111-111111111111", ID: "loopback-with-private-only", Type: "generic-ci-json",
			Endpoint: "http://127.0.0.1:8080", Provider: "build", AllowPrivate: true,
			PrivateEgressCIDRs: []string{"127.0.0.0/8"},
		},
	}
	for _, entry := range tests {
		if _, err := secretSyncTargetsFromConfig(context.Background(), []config.SecretSyncTargetConfig{entry}, nil, nil, nil); err == nil {
			t.Fatalf("cleartext HTTP secret-sync endpoint %q was accepted", entry.Endpoint)
		}
	}
}

func TestSecretIntegrationHTTPClientAllowsOnlyExplicitLoopbackPlaintext(t *testing.T) {
	const endpoint = "http://127.0.0.1:0"
	if _, err := secretIntegrationHTTPClient(endpoint, true, false, []string{"127.0.0.0/8"}, nil); err == nil {
		t.Fatal("allow_private_endpoint alone authorized loopback plaintext")
	}
	client, err := secretIntegrationHTTPClient(endpoint, false, true, nil, nil)
	if err != nil {
		t.Fatalf("explicit insecure loopback client: %v", err)
	}
	if _, err := client.Get(endpoint); err == nil || errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("loopback dial error = %v, want connection failure after passing transport policy", err)
	}
}
