// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"slices"
	"testing"
	"time"
)

// A203-L2: an engine mount lists every provider of the engine, a provider's
// own mount names it alone, and a mount that is not a dynamic engine (or a
// provider with no Vault engine shape) is left to the cubbyhole. A role reads
// as the engine's Vault role with the provider's lifetimes; a connection reads
// as its plugin and roles, with no connection details.
func TestVaultEngineConfigShapesA203L2(t *testing.T) {
	s := vaultShimSecrets(
		vaultShimProvider{id: "app-postgres", providerType: "postgresql", roles: []string{"readonly"}, maxTTL: 2 * time.Hour},
		vaultShimProvider{id: "billing-mysql", providerType: "mysql", roles: []string{"writer", "readonly"}, maxTTL: 30 * time.Minute},
		vaultShimProvider{id: "apps-k8s", providerType: "kubernetes", roles: []string{"reader"}, namespace: "apps", audience: "https://kubernetes.default.svc", maxTTL: time.Hour},
		vaultShimProvider{id: "aws-deploy", providerType: "aws-sts", roles: []string{"deployer"}, maxTTL: 12 * time.Hour},
		vaultShimProvider{id: "gcp-view", providerType: "gcp-iam", roles: []string{"viewer"}, maxTTL: time.Hour},
	)
	for _, c := range []struct {
		mount, engine string
		providers     []string
	}{
		{"database", "database", []string{"app-postgres", "billing-mysql"}},
		{"billing-mysql", "database", []string{"billing-mysql"}},
		{"kubernetes", "kubernetes", []string{"apps-k8s"}},
		{"aws", "aws", []string{"aws-deploy"}},
		{"gcp-view", "", nil},
		{"cubbyhole", "", nil},
	} {
		engine, providers := s.vaultEngineConfigProviders("tenant-a", c.mount)
		var ids []string
		for _, provider := range providers {
			ids = append(ids, provider.ID)
		}
		if engine != c.engine || !slices.Equal(ids, c.providers) {
			t.Fatalf("mount %s = %q %v, want %q %v", c.mount, engine, ids, c.engine, c.providers)
		}
	}

	_, databases := s.vaultEngineConfigProviders("tenant-a", "billing-mysql")
	role := vaultEngineRole("database", databases[0], nil)
	if role["db_name"] != "billing-mysql" || role["default_ttl"] != int64(1800) || role["max_ttl"] != int64(1800) || role["credential_type"] != "password" {
		t.Fatalf("database role = %v, want the default lowered to the provider's 30-minute maximum", role)
	}
	connection := vaultDatabaseConnection(databases[0])
	if connection["plugin_name"] != "mysql-database-plugin" || !slices.Equal(connection["allowed_roles"].([]string), []string{"readonly", "writer"}) ||
		len(connection["connection_details"].(map[string]any)) != 0 {
		t.Fatalf("database connection = %v", connection)
	}

	_, kubes := s.vaultEngineConfigProviders("tenant-a", "kubernetes")
	scope, _ := s.vaultProviderScope("tenant-a", "apps-k8s")
	kube := vaultEngineRole("kubernetes", kubes[0], scope)
	if !slices.Equal(kube["allowed_kubernetes_namespaces"].([]string), []string{"apps"}) || kube["token_max_ttl"] != int64(3600) ||
		!slices.Equal(kube["token_default_audiences"].([]string), []string{"https://kubernetes.default.svc"}) {
		t.Fatalf("kubernetes role = %v", kube)
	}
	_, awsProviders := s.vaultEngineConfigProviders("tenant-a", "aws")
	aws := vaultEngineRole("aws", awsProviders[0], nil)
	if aws["credential_type"] != "assumed_role" || aws["max_sts_ttl"] != int64(43200) || aws["default_sts_ttl"] != int64(3600) {
		t.Fatalf("aws role = %v", aws)
	}
}
