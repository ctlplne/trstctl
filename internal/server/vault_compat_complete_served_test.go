// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

var vaultServedMutationSequence atomic.Uint64

// TestVaultCompatMountACLTransitPKIProductionAssembly proves COMPLETE-SECRETS-101
// against Build's shipped handler, real PostgreSQL, the real event log, and the
// signer process. It does not construct an API route registry and has no external
// CLI availability skip.
func TestVaultCompatMountACLTransitPKIProductionAssembly(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant,
		"policy:read", "policy:write", "keys:read", "keys:write", "secrets:read", "secrets:write",
	)
	allowAll := `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`
	vaultServedRequest(t, h, token, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{"policy": allowAll}, http.StatusNoContent)

	for path, mountType := range map[string]string{
		"application-secrets": "kv-v2",
		"application-transit": "transit",
		"application-pki":     "pki",
	} {
		vaultServedRequest(t, h, token, http.MethodPost, "/v1/sys/mounts/"+path, map[string]any{
			"type": mountType, "description": "served DoD mount", "config": map[string]any{},
			"options": map[string]string{"version": "2"},
		}, http.StatusNoContent)
	}
	mounts := vaultServedRequest(t, h, token, http.MethodGet, "/v1/sys/mounts", nil, http.StatusOK)
	for _, path := range []string{"application-secrets/", "application-transit/", "application-pki/"} {
		if !bytes.Contains(mounts, []byte(`"`+path+`"`)) {
			t.Fatalf("served mount list missing %q: %s", path, mounts)
		}
	}
	discovery := vaultServedRequest(t, h, token, http.MethodGet, "/v1/sys/internal/ui/mounts/application-transit/encrypt/app", nil, http.StatusOK)
	if !bytes.Contains(discovery, []byte(`"type":"transit"`)) {
		t.Fatalf("dynamic mount discovery did not replay transit metadata: %s", discovery)
	}

	// Two mounts using the same logical path retain independent namespaces.
	vaultServedRequest(t, h, token, http.MethodPut, "/v1/secret/data/application", map[string]any{"data": map[string]string{"source": "builtin"}}, http.StatusOK)
	vaultServedRequest(t, h, token, http.MethodPut, "/v1/application-secrets/data/application", map[string]any{"data": map[string]string{"source": "mounted"}}, http.StatusOK)
	builtinKV := vaultServedRequest(t, h, token, http.MethodGet, "/v1/secret/data/application", nil, http.StatusOK)
	mountedKV := vaultServedRequest(t, h, token, http.MethodGet, "/v1/application-secrets/data/application", nil, http.StatusOK)
	if !bytes.Contains(builtinKV, []byte(`"source":"builtin"`)) || !bytes.Contains(mountedKV, []byte(`"source":"mounted"`)) {
		t.Fatalf("KV mount namespaces collapsed: builtin=%s mounted=%s", builtinKV, mountedKV)
	}

	vaultServedRequest(t, h, token, http.MethodPost, "/v1/application-transit/keys/app", map[string]any{"type": "aes256-gcm96"}, http.StatusNoContent)
	plaintext := []byte("production-assembly-transit")
	encrypted := vaultServedRequest(t, h, token, http.MethodPost, "/v1/application-transit/encrypt/app", map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}, http.StatusOK)
	ciphertext := vaultServedDataString(t, encrypted, "ciphertext")
	if !strings.HasPrefix(ciphertext, "vault:v1:") {
		t.Fatalf("served transit ciphertext = %q", ciphertext)
	}
	decrypted := vaultServedRequest(t, h, token, http.MethodPost, "/v1/application-transit/decrypt/app", map[string]any{"ciphertext": ciphertext}, http.StatusOK)
	decoded, err := base64.StdEncoding.DecodeString(vaultServedDataString(t, decrypted, "plaintext"))
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("served transit decrypt = %q err=%v, want %q", decoded, err, plaintext)
	}

	issued := vaultServedRequest(t, h, token, http.MethodPost, "/v1/application-pki/issue/default", map[string]any{
		"common_name": "svc.vault-complete.test", "ttl": "15m",
	}, http.StatusOK)
	if !bytes.Contains(issued, []byte("BEGIN CERTIFICATE")) || !bytes.Contains(issued, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("served mounted PKI response incomplete: %s", issued)
	}

	for _, eventType := range []string{
		"vault.compat.policy.put", "vault.compat.mount.enabled", "secret.created",
		"transit.key.created", "transit.encrypt", "pkisecret.issued",
	} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("production assembly did not emit/replay %q", eventType)
		}
	}
	if h.logContains(t, string(plaintext)) || h.logContains(t, "BEGIN PRIVATE KEY") {
		t.Fatal("Vault compatibility leaked transit plaintext or PKI private key into events")
	}

	// Replace the token-scoped ACL with a narrow policy. Native RBAC still allows
	// policy reads, so this 403 specifically proves the authored Vault ACL governs.
	readSecretsOnly := `path "secret/data/*" { capabilities = ["read"] }`
	vaultServedRequest(t, h, token, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{"policy": readSecretsOnly}, http.StatusNoContent)
	denied := vaultServedRequest(t, h, token, http.MethodGet, "/v1/sys/mounts", nil, http.StatusForbidden)
	if !bytes.Contains(denied, []byte("permission denied by Vault ACL policy")) {
		t.Fatalf("served ACL denial was not explicit: %s", denied)
	}
}

func vaultServedRequest(t *testing.T, h *servedHarness, token, method, path string, body any, want int) []byte {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal Vault request: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, reader)
	if err != nil {
		t.Fatalf("build Vault request: %v", err)
	}
	req.Header.Set("X-Vault-Token", token)
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		req.Header.Set("Idempotency-Key", "vault-served-"+strconv.FormatUint(vaultServedMutationSequence.Add(1), 10))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, path, err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, resp.StatusCode, want, raw)
	}
	return raw
}

func vaultServedDataString(t *testing.T, body []byte, field string) string {
	t.Helper()
	var response struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode Vault response: %v: %s", err, body)
	}
	var value string
	if err := json.Unmarshal(response.Data[field], &value); err != nil {
		t.Fatalf("decode Vault data.%s: %v: %s", field, err, body)
	}
	return value
}
