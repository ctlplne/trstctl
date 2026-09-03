// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

type previewServedDynamicProvider struct {
	dynsecret.Provider
	providerType string
	roles        []string
	revision     string
}

func (p previewServedDynamicProvider) MaximumTTL() time.Duration { return time.Hour }

func (p previewServedDynamicProvider) DynamicSecretProviderType() string { return p.providerType }

func (p previewServedDynamicProvider) DynamicSecretAllowedRoles() []string {
	return append([]string(nil), p.roles...)
}

func (p previewServedDynamicProvider) DynamicSecretConfigurationRevision() string {
	return p.revision
}

func withPreviewDynamicSecretProvider(backend dynsecret.Backend) func(*Deps) {
	return func(d *Deps) {
		d.DynamicSecretProviders = []dynsecret.Provider{previewServedDynamicProvider{
			Provider: dynsecret.NewProvider("payments-db", backend), providerType: "postgresql",
			roles: []string{"readonly-reporting", "support-read"}, revision: "runtime-revision-a",
		}}
	}
}

type servedDynamicProviderCatalog struct {
	Capability                  string `json:"capability"`
	ConfigurationMode           string `json:"configuration_mode"`
	ConfigurationChangesRestart bool   `json:"configuration_changes_require_restart"`
	SecretDelivery              string `json:"secret_delivery"`
	SupportedProviders          []struct {
		Type         string `json:"type"`
		Requirements []struct {
			Key      string `json:"key"`
			Kind     string `json:"kind"`
			Required bool   `json:"required"`
		} `json:"requirements"`
	} `json:"supported_providers"`
	ConfiguredProviders []struct {
		ID                    string   `json:"id"`
		Type                  string   `json:"type"`
		AllowedRoles          []string `json:"allowed_roles"`
		MaximumTTLSeconds     int64    `json:"maximum_ttl_seconds"`
		Ready                 bool     `json:"ready"`
		ConfigurationRevision string   `json:"configuration_revision"`
	} `json:"configured_providers"`
	Blockers     []string `json:"blockers"`
	DataHandling string   `json:"secret_data_handling"`
}

type servedDynamicLeasePreview struct {
	Capability             string   `json:"capability"`
	Operation              string   `json:"operation"`
	Ready                  bool     `json:"ready"`
	EffectFree             bool     `json:"effect_free"`
	ProviderID             string   `json:"provider_id"`
	ProviderType           string   `json:"provider_type"`
	Role                   string   `json:"role"`
	EffectiveTTLSeconds    int64    `json:"effective_ttl_seconds"`
	MaximumTTLSeconds      int64    `json:"maximum_ttl_seconds"`
	RequiredPermission     string   `json:"required_permission"`
	RequestFingerprint     string   `json:"request_fingerprint"`
	Blockers               []string `json:"blockers"`
	PreviewWrites          []string `json:"preview_writes"`
	PreviewExternalEffects []string `json:"preview_external_effects"`
	ExecuteWrites          []string `json:"execute_writes"`
	ExecuteExternalEffects []string `json:"execute_external_effects"`
	RecoverySteps          []string `json:"recovery_steps"`
	VerificationSteps      []string `json:"verification_steps"`
	DataHandling           string   `json:"secret_data_handling"`
}

// TestServedDynamicSecretCatalogAndPreviewBindTheExactRuntimeConfiguration is
// F65's missing Configure + Preview proof. The catalog is tenant-scoped and
// secret-free, preview performs zero provider calls, and a changed reviewed
// request is refused before the external backend can create a credential.
func TestServedDynamicSecretCatalogAndPreviewBindTheExactRuntimeConfiguration(t *testing.T) {
	backend := newServedDynamicSecretBackend()
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		withPreviewDynamicSecretProvider(backend),
	)
	registerServedTenant(t, h, "dynamic-secret review tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	dispatcherCtx, cancelDispatcher := context.WithCancel(context.Background())
	dispatcherDone := make(chan struct{})
	go func() {
		defer close(dispatcherDone)
		h.srv.RunDispatcher(dispatcherCtx)
	}()
	t.Cleanup(func() {
		cancelDispatcher()
		<-dispatcherDone
	})

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/providers", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("provider catalog: status %d body %s", status, body)
	}
	var catalog servedDynamicProviderCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		t.Fatalf("decode provider catalog: %v (%s)", err, body)
	}
	if catalog.Capability != "F65" || catalog.ConfigurationMode != "startup_static" ||
		!catalog.ConfigurationChangesRestart || catalog.SecretDelivery != "file_or_secret_reference" {
		t.Fatalf("catalog configuration contract = %+v", catalog)
	}
	if len(catalog.SupportedProviders) != 8 {
		t.Fatalf("supported provider count = %d, want all eight", len(catalog.SupportedProviders))
	}
	wantTypes := []string{"postgresql", "mysql", "mongodb", "aws-iam", "gcp-iam", "azure-entra", "kubernetes", "redis"}
	for i, want := range wantTypes {
		if catalog.SupportedProviders[i].Type != want || len(catalog.SupportedProviders[i].Requirements) == 0 {
			t.Fatalf("supported provider %d = %+v, want %s with structured requirements", i, catalog.SupportedProviders[i], want)
		}
	}
	if len(catalog.ConfiguredProviders) != 1 {
		t.Fatalf("configured providers = %+v", catalog.ConfiguredProviders)
	}
	configured := catalog.ConfiguredProviders[0]
	if configured.ID != "payments-db" || configured.Type != "postgresql" ||
		configured.MaximumTTLSeconds != 3600 || !configured.Ready || configured.ConfigurationRevision == "" ||
		len(configured.AllowedRoles) != 2 || configured.AllowedRoles[0] != "readonly-reporting" {
		t.Fatalf("configured provider projection = %+v", configured)
	}
	if len(catalog.Blockers) != 0 || !strings.Contains(catalog.DataHandling, "never") {
		t.Fatalf("catalog blockers/data handling = %+v / %q", catalog.Blockers, catalog.DataHandling)
	}
	for _, forbidden := range []string{"providers/payments/admin-dsn", "/etc/trstctl/provider", "dynamic-secret-dyn-ref"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("provider catalog leaked authority-bearing detail %q: %s", forbidden, body)
		}
	}

	request := map[string]any{"provider": "payments-db", "role": "readonly-reporting", "ttl_seconds": 900}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/preview", tok, request)
	if status != http.StatusOK {
		t.Fatalf("dynamic lease preview: status %d body %s", status, body)
	}
	var preview servedDynamicLeasePreview
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode dynamic lease preview: %v (%s)", err, body)
	}
	if !preview.Ready || !preview.EffectFree || preview.Capability != "F65" || preview.Operation != "issue_dynamic_secret_lease" ||
		preview.ProviderID != "payments-db" || preview.ProviderType != "postgresql" || preview.Role != "readonly-reporting" ||
		preview.EffectiveTTLSeconds != 900 || preview.MaximumTTLSeconds != 3600 ||
		preview.RequiredPermission != "secrets:write" || !strings.HasPrefix(preview.RequestFingerprint, "sha256:") ||
		len(preview.Blockers) != 0 || len(preview.PreviewWrites) != 0 || len(preview.PreviewExternalEffects) != 0 ||
		len(preview.ExecuteWrites) == 0 || len(preview.ExecuteExternalEffects) == 0 ||
		len(preview.RecoverySteps) == 0 || len(preview.VerificationSteps) == 0 || !strings.Contains(preview.DataHandling, "once") {
		t.Fatalf("dynamic lease preview = %+v", preview)
	}
	backend.mu.Lock()
	createdBefore := backend.n
	backend.mu.Unlock()
	if createdBefore != 0 {
		t.Fatalf("effect-free preview created %d backend credentials", createdBefore)
	}

	stale := map[string]any{
		"provider": "payments-db", "role": "support-read", "ttl_seconds": 900,
		"preview_fingerprint": preview.RequestFingerprint,
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "f65-stale-review", stale)
	if status != http.StatusConflict || !strings.Contains(string(body), "reviewed dynamic-secret plan is stale") {
		t.Fatalf("stale reviewed issue: status %d body %s", status, body)
	}
	backend.mu.Lock()
	createdAfterStale := backend.n
	backend.mu.Unlock()
	if createdAfterStale != 0 {
		t.Fatalf("stale review created %d backend credentials", createdAfterStale)
	}

	request["preview_fingerprint"] = preview.RequestFingerprint
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "f65-reviewed-issue", request)
	if status != http.StatusCreated {
		t.Fatalf("reviewed dynamic lease issue: status %d body %s", status, body)
	}
	backend.mu.Lock()
	createdAfterIssue := backend.n
	backend.mu.Unlock()
	if createdAfterIssue != 1 {
		t.Fatalf("reviewed issue created %d backend credentials, want one", createdAfterIssue)
	}
}
