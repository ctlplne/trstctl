// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

var vaultShimRequestSequence atomic.Uint64

// vaultShimRequest drives the served Vault/OpenBao shim the way a stock client
// does: X-Vault-Token, JSON, and an Idempotency-Key on mutations.
func vaultShimRequest(t *testing.T, h *servedHarness, token, method, path string, body any) (int, map[string]any, []byte) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		if encoded, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, h.ts.URL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "vault-shim-"+strconv.FormatUint(vaultShimRequestSequence.Add(1), 10))
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	return resp.StatusCode, decoded, raw
}

// A migrating team's `vault kv` tooling lists folders, reads version metadata
// and deletes objects, and `vault token` tooling asks for capabilities. The shim
// serves those KV v2 and token paths over the native store: metadata shows every
// retained version, LIST (and GET ?list=true) returns the direct children of a
// folder with folders suffixed "/", DELETE on data or metadata removes the
// object, capabilities-self answers from the token's permissions and ACLs, and
// renew-self says honestly that API tokens are not renewable.
func TestServedVaultShimKVMetadataListDeleteAndTokenPaths(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "vault shim kv metadata tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	put := func(name, password string) {
		t.Helper()
		if code, _, raw := vaultShimRequest(t, h, token, http.MethodPut, "/v1/secret/data/"+name, map[string]any{"data": map[string]string{"password": password}}); code != http.StatusOK {
			t.Fatalf("kv put %s: %d %s", name, code, raw)
		}
	}
	put("app/db", "one")
	put("app/db", "two")
	put("app/cache", "c")
	put("app/nested/leaf", "n")

	code, meta, raw := vaultShimRequest(t, h, token, http.MethodGet, "/v1/secret/metadata/app/db", nil)
	if code != http.StatusOK {
		t.Fatalf("metadata get: %d %s", code, raw)
	}
	data, _ := meta["data"].(map[string]any)
	if cv, _ := data["current_version"].(float64); cv != 2 {
		t.Fatalf("metadata current_version = %v; want 2: %s", data["current_version"], raw)
	}
	versions, _ := data["versions"].(map[string]any)
	if len(versions) != 2 || versions["1"] == nil || versions["2"] == nil {
		t.Fatalf("metadata versions = %v; want versions 1 and 2", versions)
	}

	for _, probe := range []struct{ method, path string }{{"LIST", "/v1/secret/metadata/app"}, {http.MethodGet, "/v1/secret/metadata/app?list=true"}} {
		code, body, raw := vaultShimRequest(t, h, token, probe.method, probe.path, nil)
		if code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", probe.method, probe.path, code, raw)
		}
		keys, _ := body["data"].(map[string]any)["keys"].([]any)
		if len(keys) != 3 || keys[0] != "cache" || keys[1] != "db" || keys[2] != "nested/" {
			t.Fatalf("%s keys = %v; want [cache db nested/]: %s", probe.method, keys, raw)
		}
	}
	if code, _, raw := vaultShimRequest(t, h, token, "LIST", "/v1/secret/metadata/nowhere", nil); code != http.StatusNotFound {
		t.Fatalf("LIST of an empty folder: %d %s; want 404 like Vault", code, raw)
	}

	code, caps, raw := vaultShimRequest(t, h, token, http.MethodPost, "/v1/sys/capabilities-self", map[string]any{"paths": []string{"secret/data/app/db", "sys/policies/acl/x"}})
	if code != http.StatusOK {
		t.Fatalf("capabilities-self: %d %s", code, raw)
	}
	capData, _ := caps["data"].(map[string]any)
	dbCaps, _ := capData["secret/data/app/db"].([]any)
	if len(dbCaps) == 0 || !containsAnyString(dbCaps, "read") || !containsAnyString(dbCaps, "update") {
		t.Fatalf("capabilities for secret/data/app/db = %v; want read and update for a secrets:read+write token: %s", dbCaps, raw)
	}
	aclCaps, _ := capData["sys/policies/acl/x"].([]any)
	if len(aclCaps) != 1 || aclCaps[0] != "deny" {
		t.Fatalf("capabilities for sys/policies/acl/x = %v; want [deny] without policy:write: %s", aclCaps, raw)
	}

	code, _, raw = vaultShimRequest(t, h, token, http.MethodPost, "/v1/auth/token/renew-self", map[string]any{"increment": "1h"})
	if code != http.StatusBadRequest || !bytes.Contains(raw, []byte("not renewable")) {
		t.Fatalf("renew-self: %d %s; want 400 saying the token is not renewable", code, raw)
	}

	if code, _, raw := vaultShimRequest(t, h, token, http.MethodDelete, "/v1/secret/data/app/cache", nil); code != http.StatusNoContent {
		t.Fatalf("delete data: %d %s", code, raw)
	}
	if code, _, raw := vaultShimRequest(t, h, token, http.MethodGet, "/v1/secret/data/app/cache", nil); code != http.StatusNotFound {
		t.Fatalf("read after delete: %d %s; want 404", code, raw)
	}
	if code, _, raw := vaultShimRequest(t, h, token, http.MethodDelete, "/v1/secret/metadata/app/nested/leaf", nil); code != http.StatusNoContent {
		t.Fatalf("delete metadata: %d %s", code, raw)
	}
	code, body, raw := vaultShimRequest(t, h, token, "LIST", "/v1/secret/metadata/app", nil)
	keys, _ := body["data"].(map[string]any)["keys"].([]any)
	if code != http.StatusOK || len(keys) != 1 || keys[0] != "db" {
		t.Fatalf("LIST after deletes: %d keys=%v %s; want [db]", code, keys, raw)
	}
}

func containsAnyString(values []any, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
