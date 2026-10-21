// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// Response wrapping and the cubbyhole are the two Vault conveniences the shim
// still refused. Wrapping stores a one-time payload under a single-use wrapping
// token (the same durable, tenant-scoped share rows the native one-time share
// uses): lookup reports its creation time and TTL without consuming it, unwrap
// returns the payload exactly once. The cubbyhole is a per-token scratch space:
// another token cannot read it, listing shows a token's own paths, and delete
// removes one.
func TestServedVaultShimResponseWrappingAndCubbyhole(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "vault shim wrapping tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	other := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	code, wrapped, raw := vaultShimRequest(t, h, token, http.MethodPost, "/v1/sys/wrapping/wrap", map[string]any{"password": "once-only"})
	if code != http.StatusOK {
		t.Fatalf("wrap: %d %s", code, raw)
	}
	wrapInfo, _ := wrapped["wrap_info"].(map[string]any)
	wrapToken, _ := wrapInfo["token"].(string)
	if wrapToken == "" || wrapInfo["ttl"] == nil || wrapInfo["creation_time"] == nil {
		t.Fatalf("wrap_info = %v; want token, ttl and creation_time: %s", wrapInfo, raw)
	}
	if bytes.Contains(raw, []byte("once-only")) {
		t.Fatal("wrap echoed the payload")
	}
	code, lookup, raw := vaultShimRequest(t, h, token, http.MethodPost, "/v1/sys/wrapping/lookup", map[string]any{"token": wrapToken})
	if code != http.StatusOK || lookup["data"].(map[string]any)["creation_ttl"] == nil {
		t.Fatalf("lookup: %d %s; want creation_ttl without consuming", code, raw)
	}
	code, unwrapped, raw := vaultShimRequest(t, h, token, http.MethodPost, "/v1/sys/wrapping/unwrap", map[string]any{"token": wrapToken})
	if code != http.StatusOK || unwrapped["data"].(map[string]any)["password"] != "once-only" {
		t.Fatalf("unwrap: %d %s", code, raw)
	}
	if code, _, raw := vaultShimRequest(t, h, token, http.MethodPost, "/v1/sys/wrapping/unwrap", map[string]any{"token": wrapToken}); code != http.StatusBadRequest {
		t.Fatalf("second unwrap: %d %s; want 400 (consumed)", code, raw)
	}

	if code, _, raw := vaultShimRequest(t, h, token, http.MethodPost, "/v1/cubbyhole/scratch/note", map[string]any{"value": "mine"}); code != http.StatusNoContent {
		t.Fatalf("cubbyhole write: %d %s", code, raw)
	}
	code, got, raw := vaultShimRequest(t, h, token, http.MethodGet, "/v1/cubbyhole/scratch/note", nil)
	if code != http.StatusOK || got["data"].(map[string]any)["value"] != "mine" {
		t.Fatalf("cubbyhole read: %d %s", code, raw)
	}
	if code, _, raw := vaultShimRequest(t, h, other, http.MethodGet, "/v1/cubbyhole/scratch/note", nil); code != http.StatusNotFound {
		t.Fatalf("another token read the cubbyhole: %d %s", code, raw)
	}
	code, listed, raw := vaultShimRequest(t, h, token, "LIST", "/v1/cubbyhole/scratch", nil)
	keys, _ := listed["data"].(map[string]any)["keys"].([]any)
	if code != http.StatusOK || len(keys) != 1 || keys[0] != "note" {
		t.Fatalf("cubbyhole list: %d keys=%v %s", code, keys, raw)
	}
	if code, _, raw := vaultShimRequest(t, h, token, http.MethodDelete, "/v1/cubbyhole/scratch/note", nil); code != http.StatusNoContent {
		t.Fatalf("cubbyhole delete: %d %s", code, raw)
	}
	if code, _, _ := vaultShimRequest(t, h, token, http.MethodGet, "/v1/cubbyhole/scratch/note", nil); code != http.StatusNotFound {
		t.Fatalf("cubbyhole read after delete: %d; want 404", code)
	}
}
