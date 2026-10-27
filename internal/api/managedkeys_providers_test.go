// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// providerRecordingManagedKeys records the provider each call names.
type providerRecordingManagedKeys struct {
	stubManagedKeys
	providers []string
}

func (s *providerRecordingManagedKeys) Generate(ctx context.Context, tenantID, provider string, alg crypto.Algorithm, idempotencyKey, requestBinding string) (api.ManagedKey, error) {
	s.providers = append(s.providers, provider)
	key, err := s.stubManagedKeys.Generate(ctx, tenantID, provider, alg, idempotencyKey, requestBinding)
	key.Provider = "aws-kms"
	return key, err
}

func (s *providerRecordingManagedKeys) Rotate(ctx context.Context, tenantID, provider, keyID, requester, idempotencyKey, requestBinding string) (api.ManagedKey, error) {
	s.providers = append(s.providers, provider)
	key, err := s.stubManagedKeys.Rotate(ctx, tenantID, provider, keyID, requester, idempotencyKey, requestBinding)
	key.Provider = "aws-kms"
	return key, err
}

// A199: the custody posture lists every provider the deployment runs and the
// caller tenant's pin; a pinned tenant generates only under its pin; a key
// reports its provider; an action may name the key's provider as the
// inventory reports it.
func TestManagedKeysOfferEveryConfiguredProviderAndHonorTenantPins(t *testing.T) {
	service := &providerRecordingManagedKeys{}
	handler := api.New(nil, orchestrator.NewMemoryIdempotency(), nil, api.WithInsecureHeaderResolver(),
		api.WithManagedKeyCustody(api.ManagedKeyCustodyConfiguration{
			Enabled: true, Provider: "pkcs11", Providers: []string{"pkcs11", "AWS"},
			TenantProviders: map[string]string{managedKeyTestTenant: "aws"},
		}),
		api.WithManagedKeys(service))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/managed-keys/custody", nil)
	req.Header.Set("X-Tenant-ID", managedKeyTestTenant)
	req.Header.Set("X-Subject", "operator-a")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var plan api.ManagedKeyCustodyPlan
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("custody = %d %v", rec.Code, err)
	}
	if plan.ConfiguredProvider != "pkcs11" || !slices.Equal(plan.ConfiguredProviders, []string{"pkcs11", "aws"}) || plan.TenantProvider != "aws" {
		t.Fatalf("custody plan = default %q providers %v tenant %q", plan.ConfiguredProvider, plan.ConfiguredProviders, plan.TenantProvider)
	}

	preview := managedKeyRequest(t, handler, "/api/v1/managed-keys/preview", "", "operator-a", `{"provider":"pkcs11","algorithm":"ECDSA-P256"}`)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), "pinned to aws") || !strings.Contains(preview.Body.String(), `"ready":false`) {
		t.Fatalf("preview under another provider = %d %s", preview.Code, preview.Body.String())
	}
	for _, refused := range []string{"pkcs11", "gcp-kms"} {
		rec := managedKeyRequest(t, handler, "/api/v1/managed-keys", "generate-"+refused, "operator-a", `{"provider":"`+refused+`","algorithm":"ECDSA-P256"}`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("generate under %s = %d %s, want 409", refused, rec.Code, rec.Body.String())
		}
	}
	if len(service.providers) != 0 {
		t.Fatalf("refused requests reached the service: %v", service.providers)
	}
	generated := managedKeyRequest(t, handler, "/api/v1/managed-keys", "generate-aws", "operator-a", `{"provider":"aws","algorithm":"ECDSA-P256"}`)
	if generated.Code != http.StatusCreated || !strings.Contains(generated.Body.String(), `"provider":"aws-kms"`) {
		t.Fatalf("generate under the pin = %d %s", generated.Code, generated.Body.String())
	}
	rotated := managedKeyRequest(t, handler, "/api/v1/managed-keys/rotate", "rotate-aws", "operator-a", `{"key_id":"fake-kms-key-0001","provider":"aws-kms"}`)
	if rotated.Code != http.StatusOK || !strings.Contains(rotated.Body.String(), `"provider":"aws-kms"`) {
		t.Fatalf("rotate naming the inventory provider = %d %s", rotated.Code, rotated.Body.String())
	}
	if !slices.Equal(service.providers, []string{"aws", "aws-kms"}) {
		t.Fatalf("providers reaching the service = %v", service.providers)
	}
	if rec := managedKeyRequest(t, handler, "/api/v1/managed-keys/rotate", "rotate-gcp", "operator-a", `{"key_id":"fake-kms-key-0001","provider":"gcp-kms"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("rotate naming a provider the deployment does not run = %d %s", rec.Code, rec.Body.String())
	}
}
