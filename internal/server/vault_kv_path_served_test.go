// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/policy"
)

type canonicalKVPathDeny struct{ active *atomic.Bool }

func (d canonicalKVPathDeny) EvaluateDeny(_ context.Context, in policy.ABACInput) (policy.ABACDecision, error) {
	if d.active.Load() && in.Permission == "secrets:read" && in.Resource["request.path"] == "/v1/secret/data/app/db" {
		return policy.ABACDecision{Deny: true, Reason: "canonical KV path is restricted"}, nil
	}
	return policy.ABACDecision{}, nil
}

func TestServedVaultKVUsesOneCanonicalSecretPath(t *testing.T) {
	var deny atomic.Bool
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithABACDenyOverlay(canonicalKVPathDeny{active: &deny}, nil, nil))
	})
	registerServedTenant(t, h, "Vault KV path tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "policy:read", "policy:write")
	write := map[string]any{"data": map[string]string{"value": "fixture"}}
	if status, _, raw := vaultShimRequest(t, h, token, http.MethodPut, "/v1/secret/data/app/db", write); status != http.StatusOK {
		t.Fatalf("canonical KV write = %d %s", status, raw)
	}
	if status, _, raw := vaultShimRequest(t, h, token, http.MethodGet, "/v1/secret/data/app%2Fdb", nil); status != http.StatusOK {
		t.Fatalf("encoded separator KV read = %d %s", status, raw)
	}
	if status, _, raw := vaultShimRequest(t, h, token, http.MethodPost, "/v1/sys/mounts/application-secrets",
		map[string]any{"type": "kv-v2", "options": map[string]string{"version": "2"}}); status != http.StatusNoContent {
		t.Fatalf("mounted KV setup = %d %s", status, raw)
	}
	if status, _, raw := vaultShimRequest(t, h, token, http.MethodPut, "/v1/application-secrets/data/app/db", write); status != http.StatusOK {
		t.Fatalf("mounted KV write = %d %s", status, raw)
	}
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/v1/secret/data/%2Fapp/db", nil},
		{http.MethodPut, "/v1/secret/data/%2Fapp/db", write},
		{http.MethodDelete, "/v1/secret/metadata/%2Fapp/db", nil},
		{http.MethodGet, "/v1/secret/data/app%2F%2Fdb", nil},
		{http.MethodGet, "/v1/secret/data/app/%2E%2E/db", nil},
		{http.MethodGet, "/v1/application-secrets/data/%2Fapp/db", nil},
	} {
		status, _, raw := vaultShimRequest(t, h, token, tc.method, tc.path, tc.body)
		if status != http.StatusBadRequest {
			t.Fatalf("%s %s = %d, want 400: %s", tc.method, tc.path, status, raw)
		}
	}
	if status, _, raw := vaultShimRequest(t, h, token, http.MethodGet, "/v1/secret/data/app/db", nil); status != http.StatusOK {
		t.Fatalf("canonical KV read after refused names = %d %s", status, raw)
	}
	deny.Store(true)
	for _, path := range []string{"/v1/secret/data/app/db", "/v1/secret/data/app%2Fdb"} {
		if status, _, raw := vaultShimRequest(t, h, token, http.MethodGet, path, nil); status != http.StatusForbidden {
			t.Fatalf("restricted KV read %s = %d, want 403: %s", path, status, raw)
		}
	}
}
