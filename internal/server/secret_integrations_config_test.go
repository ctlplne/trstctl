// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/netsec"
)

type configuredDynamicBackendFixture struct {
	createErr error
	revokeErr error
	created   []dynsecret.GenerateRequest
	prepared  [][]byte
	revoked   []string
	closed    int
}

func (b *configuredDynamicBackendFixture) CreateCredential(_ context.Context, req dynsecret.GenerateRequest) (string, []byte, error) {
	b.created = append(b.created, req)
	if b.createErr != nil {
		return "", nil, b.createErr
	}
	return "native-ref", []byte("short-lived-secret"), nil
}

func (b *configuredDynamicBackendFixture) CreatePreparedCredential(_ context.Context, req dynsecret.GenerateRequest, prepared []byte) (string, []byte, error) {
	b.created = append(b.created, req)
	b.prepared = append(b.prepared, bytes.Clone(prepared))
	if b.createErr != nil {
		return "", nil, b.createErr
	}
	return "prepared-native-ref", []byte("prepared-short-lived-secret"), nil
}

func (b *configuredDynamicBackendFixture) Revoke(_ context.Context, ref string) error {
	b.revoked = append(b.revoked, ref)
	return b.revokeErr
}

func (b *configuredDynamicBackendFixture) Close() { b.closed++ }

func TestConfiguredDynamicProviderEnforcesRoleTTLAndBackendLifecycle(t *testing.T) {
	backend := &configuredDynamicBackendFixture{}
	provider := &configuredDynamicProvider{
		id: "postgres-production", tenantID: "tenant-a",
		cfg:          config.DynamicSecretProviderConfig{Type: "postgresql"},
		allowedRoles: map[string]bool{"reader": true}, maxTTL: time.Hour,
	}
	provider.open = func(context.Context) (requestDynamicBackend, func(), error) {
		return backend, backend.Close, nil
	}
	if provider.Name() != "postgres-production" || provider.MaximumTTL() != time.Hour {
		t.Fatalf("provider identity/TTL = %q/%s", provider.Name(), provider.MaximumTTL())
	}
	req := dynsecret.GenerateRequest{Role: "reader", TTL: 15 * time.Minute, LeaseID: "lease-a"}
	credential, err := provider.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if credential.BackendRef != "native-ref" || !bytes.Equal(credential.Secret, []byte("short-lived-secret")) || credential.Metadata["provider_type"] != "postgresql" {
		t.Fatalf("generated credential = %+v", credential)
	}
	secret.Wipe(credential.Secret)
	if len(backend.created) != 1 || backend.closed != 1 {
		t.Fatalf("backend calls created=%+v closed=%d", backend.created, backend.closed)
	}

	for _, invalid := range []dynsecret.GenerateRequest{
		{Role: "writer", TTL: time.Minute},
		{Role: "reader", TTL: 0},
		{Role: "reader", TTL: 2 * time.Hour},
	} {
		if _, err := provider.Generate(context.Background(), invalid); err == nil {
			t.Fatalf("Generate(%+v) succeeded", invalid)
		}
	}
	if len(backend.created) != 1 {
		t.Fatalf("invalid request reached backend: %+v", backend.created)
	}

	if err := provider.Revoke(context.Background(), "native-ref"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(backend.revoked) != 1 || backend.revoked[0] != "native-ref" || backend.closed != 2 {
		t.Fatalf("backend revocation=%+v closed=%d", backend.revoked, backend.closed)
	}

	prepared := &configuredPreparedDynamicProvider{configuredDynamicProvider: provider}
	preparedCredential, err := prepared.GeneratePrepared(context.Background(), req, []byte("sealed-preparation"))
	if err != nil {
		t.Fatalf("GeneratePrepared: %v", err)
	}
	secret.Wipe(preparedCredential.Secret)
	if len(backend.prepared) != 1 || !bytes.Equal(backend.prepared[0], []byte("sealed-preparation")) {
		t.Fatalf("prepared backend inputs = %q", backend.prepared)
	}
	if _, err := prepared.Prepare(context.Background(), dynsecret.GenerateRequest{}); err == nil {
		t.Fatal("GCP preparation accepted a request without stable lease identity/TTL")
	}

	backend.createErr = errors.New("native create failed")
	if _, err := provider.Generate(context.Background(), req); !errors.Is(err, backend.createErr) {
		t.Fatalf("backend create error = %v", err)
	}
	backend.revokeErr = errors.New("native revoke failed")
	if err := provider.Revoke(context.Background(), "native-ref"); !errors.Is(err, backend.revokeErr) {
		t.Fatalf("backend revoke error = %v", err)
	}
}

func TestConfiguredDynamicProviderFailsClosedWhenOpenerIsMissingOrFails(t *testing.T) {
	provider := &configuredDynamicProvider{
		id: "missing", allowedRoles: map[string]bool{"reader": true}, maxTTL: time.Hour,
	}
	req := dynsecret.GenerateRequest{Role: "reader", TTL: time.Minute}
	if _, err := provider.Generate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "opener") {
		t.Fatalf("missing opener error = %v", err)
	}
	if err := provider.Revoke(context.Background(), "native-ref"); err == nil || !strings.Contains(err.Error(), "opener") {
		t.Fatalf("missing revoke opener error = %v", err)
	}
	wantErr := errors.New("backend unavailable")
	provider.open = func(context.Context) (requestDynamicBackend, func(), error) {
		return nil, func() {}, wantErr
	}
	if _, err := provider.Generate(context.Background(), req); !errors.Is(err, wantErr) {
		t.Fatalf("Generate opener error = %v", err)
	}
	if err := provider.Revoke(context.Background(), "native-ref"); !errors.Is(err, wantErr) {
		t.Fatalf("Revoke opener error = %v", err)
	}

	provider.cfg.Type = "unknown"
	if _, _, err := openConfiguredDynamicBackend(context.Background(), provider); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported backend error = %v", err)
	}
}

func TestIntegrationCredentialResolverUsesCustodyCheckedFilesAndRejectsAmbientValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "provider-credential")
	value := []byte("operator-authority")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := integrationCredentialResolver{}
	locked, err := resolver.resolve(context.Background(), "tenant-a", "file:"+path)
	if err != nil {
		t.Fatalf("resolve custody-checked file: %v", err)
	}
	if !bytes.Equal(locked.Bytes(), value) {
		t.Fatalf("resolved credential bytes = %q", locked.Bytes())
	}
	locked.Destroy()
	for _, ref := range []string{"literal-authority", "secret://", "secret://provider/admin"} {
		if _, err := resolver.resolve(context.Background(), "tenant-a", ref); err == nil {
			t.Fatalf("resolve(%q) succeeded without an authorized custody source", ref)
		}
	}
	if got := string(secretIntegrationStoreAAD("tenant-a", "provider/admin")); got != "tenant-a/secret-store/provider/admin" {
		t.Fatalf("secret-store AAD = %q", got)
	}
}

func TestConfiguredBackendOpenersConstructEveryNetworklessProvider(t *testing.T) {
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "provider-admin")
	if err := os.WriteFile(credentialPath, []byte("operator-authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	credentialRef := "file:" + credentialPath
	tests := []config.DynamicSecretProviderConfig{
		{Type: "postgresql", AdminDSNRef: credentialRef, Database: "app"},
		{Type: "redis", Addr: "redis.internal:6379", PasswordRef: credentialRef},
		{Type: "kubernetes", Endpoint: "https://kubernetes.example.test", Namespace: "apps", BearerTokenRef: credentialRef},
		{Type: "aws-iam", Endpoint: "https://iam.example.test", Region: "us-east-1", AccessKeyID: "AKID", SecretAccessRef: credentialRef},
		{Type: "gcp-iam", Endpoint: "https://iam.example.test", Project: "project-a", ServiceAccount: "issuer@example.test", BearerTokenRef: credentialRef},
		{Type: "azure-entra", Endpoint: "https://graph.example.test", ApplicationObject: "object-a", ApplicationClient: "client-a", AzureTenant: "tenant-a", BearerTokenRef: credentialRef},
	}
	for _, cfg := range tests {
		t.Run(cfg.Type, func(t *testing.T) {
			provider := &configuredDynamicProvider{
				id: "provider-" + cfg.Type, tenantID: "tenant-a", cfg: cfg,
				credentials: integrationCredentialResolver{},
			}
			backend, cleanup, err := openConfiguredDynamicBackend(context.Background(), provider)
			if err != nil {
				t.Fatalf("openConfiguredDynamicBackend(%s): %v", cfg.Type, err)
			}
			if backend == nil || cleanup == nil {
				t.Fatalf("openConfiguredDynamicBackend(%s) backend=%T cleanup_configured=%t", cfg.Type, backend, cleanup != nil)
			}
			cleanup()
		})
	}

	for _, cfg := range []config.DynamicSecretProviderConfig{
		{Type: "mysql", Database: "app"},
		{Type: "mongodb", Database: "app"},
	} {
		t.Run(cfg.Type+"-missing-admin", func(t *testing.T) {
			provider := &configuredDynamicProvider{id: cfg.Type, tenantID: "tenant-a", cfg: cfg}
			if _, _, err := openConfiguredDynamicBackend(context.Background(), provider); err == nil {
				t.Fatalf("partially configured %s backend succeeded", cfg.Type)
			}
		})
	}
}

type adapterBackendFixture struct {
	prepared bool
}

func (*adapterBackendFixture) Create(context.Context, string) (string, []byte, error) {
	return "adapter-ref", []byte("adapter-secret"), nil
}

func (*adapterBackendFixture) Revoke(context.Context, string) error { return nil }

func (b *adapterBackendFixture) CreatePreparedCredential(context.Context, dynsecret.GenerateRequest, []byte) (string, []byte, error) {
	b.prepared = true
	return "prepared-adapter-ref", []byte("prepared-adapter-secret"), nil
}

type legacyAdapterBackendFixture struct{}

func (legacyAdapterBackendFixture) Create(context.Context, string) (string, []byte, error) {
	return "legacy-ref", []byte("legacy-secret"), nil
}

func (legacyAdapterBackendFixture) Revoke(context.Context, string) error { return nil }

func TestRequestBackendAdapterPreservesPreparedCapability(t *testing.T) {
	backend := &adapterBackendFixture{}
	adapter := &requestBackendAdapter{Backend: backend}
	ref, value, err := adapter.CreateCredential(context.Background(), dynsecret.GenerateRequest{Role: "reader"})
	if err != nil || ref != "adapter-ref" || !bytes.Equal(value, []byte("adapter-secret")) {
		t.Fatalf("CreateCredential = %q, %q, %v", ref, value, err)
	}
	secret.Wipe(value)
	ref, value, err = adapter.CreatePreparedCredential(context.Background(), dynsecret.GenerateRequest{Role: "reader"}, []byte("prepared"))
	if err != nil || ref != "prepared-adapter-ref" || !backend.prepared {
		t.Fatalf("CreatePreparedCredential = %q, %q, %v prepared=%v", ref, value, err, backend.prepared)
	}
	secret.Wipe(value)
	legacy := &requestBackendAdapter{Backend: legacyAdapterBackendFixture{}}
	if _, _, err := legacy.CreatePreparedCredential(context.Background(), dynsecret.GenerateRequest{}, []byte("prepared")); err == nil {
		t.Fatal("legacy backend accepted durable preparation it cannot reconcile")
	}
}

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
