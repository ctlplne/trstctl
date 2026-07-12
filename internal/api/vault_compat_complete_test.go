// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	configpkg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/transit"
)

const (
	vaultCompleteTenantA = "11111111-1111-4111-8111-111111111111"
	vaultCompleteTenantB = "22222222-2222-4222-8222-222222222222"
)

// TestVaultCompatMountACLTransitServedAndReplayed is a non-skipping HTTP-wire
// proof against API.New's shipped mux. It covers mutable mount/ACL authoring,
// tenant isolation and event replay, plus the native transit adapter's stock
// Vault request/response shapes.
func TestVaultCompatMountACLTransitServedAndReplayed(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, configpkg.NATS{Mode: configpkg.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	restricted := authz.Role{Name: "restricted", Permissions: []authz.Permission{
		authz.PolicyRead, authz.PolicyWrite, authz.KeysRead, authz.KeysWrite,
	}}
	transitService := transit.NewService(audit.NewAuditor(log))
	t.Cleanup(transitService.Destroy)
	newHandler := func() http.Handler {
		return New(nil, orchestrator.NewMemoryIdempotency(), nil,
			WithInsecureHeaderResolver(), WithRoles(restricted), WithEventLog(log), WithTransit(transitService))
	}
	handler := newHandler()

	adminPolicy := `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`
	vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPut, "/v1/sys/policies/acl/admin", map[string]any{"policy": adminPolicy}, http.StatusNoContent)
	vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPost, "/v1/sys/mounts/application-secrets", map[string]any{
		"type": "kv", "description": "application KV", "options": map[string]string{"version": "2"},
	}, http.StatusNoContent)

	mounts := vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodGet, "/v1/sys/mounts", nil, http.StatusOK)
	if !bytes.Contains(mounts, []byte(`"application-secrets/"`)) || !bytes.Contains(mounts, []byte(`"transit/"`)) {
		t.Fatalf("mount list does not expose authored KV and served transit mounts: %s", mounts)
	}
	otherTenant := vaultRequest(t, handler, vaultCompleteTenantB, "admin", http.MethodGet, "/v1/sys/mounts", nil, http.StatusOK)
	if bytes.Contains(otherTenant, []byte(`"application-secrets/"`)) {
		t.Fatalf("tenant B observed tenant A mount: %s", otherTenant)
	}

	// A fresh API projection over the same append-only log sees tenant A's mount
	// and policy without sharing a process-local registry.
	handler = newHandler()
	replayed := vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodGet, "/v1/sys/internal/ui/mounts/application-secrets/data/app", nil, http.StatusOK)
	if !bytes.Contains(replayed, []byte(`"path":"application-secrets/"`)) {
		t.Fatalf("replayed mount discovery response: %s", replayed)
	}

	restrictedPolicy := `path "transit/encrypt/+" { capabilities = ["update"] }`
	vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPut, "/v1/sys/policies/acl/restricted", map[string]any{"policy": restrictedPolicy}, http.StatusNoContent)
	denied := vaultRequest(t, handler, vaultCompleteTenantA, "restricted", http.MethodPost, "/v1/sys/mounts/forbidden", map[string]any{"type": "kv"}, http.StatusForbidden)
	if !bytes.Contains(denied, []byte("permission denied by Vault ACL policy")) {
		t.Fatalf("ACL denial response: %s", denied)
	}

	vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPost, "/v1/transit/keys/app", map[string]any{"type": "aes256-gcm96"}, http.StatusNoContent)
	plaintext := []byte("vault-transit-wire-value")
	encrypted := vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPost, "/v1/transit/encrypt/app", map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}, http.StatusOK)
	ciphertext := vaultResponseString(t, encrypted, "ciphertext")
	if !stringsHasPrefix(ciphertext, "vault:v1:") {
		t.Fatalf("ciphertext = %q, want Vault versioned value", ciphertext)
	}
	decrypted := vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPost, "/v1/transit/decrypt/app", map[string]any{"ciphertext": ciphertext}, http.StatusOK)
	decoded, err := base64.StdEncoding.DecodeString(vaultResponseString(t, decrypted, "plaintext"))
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("decrypt plaintext = %q err=%v, want %q", decoded, err, plaintext)
	}

	vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPost, "/v1/transit/keys/signer", map[string]any{"type": "ecdsa-p256"}, http.StatusNoContent)
	signed := vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPost, "/v1/transit/sign/signer", map[string]any{
		"input": base64.StdEncoding.EncodeToString(plaintext),
	}, http.StatusOK)
	signature := vaultResponseString(t, signed, "signature")
	verified := vaultRequest(t, handler, vaultCompleteTenantA, "admin", http.MethodPost, "/v1/transit/verify/signer", map[string]any{
		"input": base64.StdEncoding.EncodeToString(plaintext), "signature": signature,
	}, http.StatusOK)
	if !bytes.Contains(verified, []byte(`"valid":true`)) {
		t.Fatalf("verify response: %s", verified)
	}
}

func vaultRequest(t *testing.T, handler http.Handler, tenantID, role, method, target string, body any, wantStatus int) []byte {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s %s body: %v", method, target, err)
		}
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", role+"-subject")
	req.Header.Set("X-Roles", role)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != wantStatus {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, target, res.Code, wantStatus, res.Body.Bytes())
	}
	return append([]byte(nil), res.Body.Bytes()...)
}

func vaultResponseString(t *testing.T, body []byte, field string) string {
	t.Helper()
	var response struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode Vault response: %v: %s", err, body)
	}
	value, ok := response.Data[field].(string)
	if !ok {
		t.Fatalf("Vault response data.%s is not a string: %#v", field, response.Data[field])
	}
	return value
}

func stringsHasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
