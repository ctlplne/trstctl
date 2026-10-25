// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// Owner decision 2026-10-24: PKI-secret issuance by common name, and the
// Vault-compatible pki/issue route, generate the subject key in the control
// plane, so the tenant's switch governs them. With it off both are refused
// before anything is recorded or generated, naming the CSR route; the CSR
// routes keep working, and turning the switch on restores the old ones.
func TestServedKeygenOffRefusesPKISecretsByCommonName(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedTokenSubject(t, h.store, h.tenant, "alice@customer.test",
		"secrets:read", "secrets:write", "audit:read", "policy:read", "policy:write", "access:read", "access:write")
	vaultServedRequest(t, h, token, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{
		"policy": `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`,
	}, http.StatusNoContent)
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", token, "cpk-off",
		map[string]any{"enabled": false, "reason": "requesters bring their own keys"}); status != http.StatusOK {
		t.Fatalf("turn off = %d %s", status, body)
	}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token, "pki-cn-off",
		map[string]any{"common_name": "keygen-off.example.test", "ttl_seconds": 900})
	if status != http.StatusConflict || !bytes.Contains(body, []byte("control_plane_keygen_off")) ||
		!bytes.Contains(body, []byte("csr_pem")) || bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatalf("PKI secret by common name while off = %d %s, want 409 naming csr_pem and no key", status, body)
	}
	issued := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/issue/default", "vault-issue-off",
		map[string]any{"common_name": "vault-off.example.test", "ttl": "15m"}, http.StatusConflict)
	if !bytes.Contains(issued, []byte("pki/sign")) || bytes.Contains(issued, []byte("PRIVATE KEY")) {
		t.Fatalf("Vault pki/issue while off = %s, want a refusal naming pki/sign and no key", issued)
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 0 {
		t.Fatalf("refused requests recorded %d server-side key generations", got)
	}

	// The CSR routes are what the refusals name, and they keep working.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "keygen-off.example.test"}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token, "pki-csr-off",
		map[string]any{"csr_pem": string(csrPEM), "ttl_seconds": 900}); status != http.StatusCreated {
		t.Fatalf("PKI secret by CSR while off = %d %s", status, body)
	}
	signed := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/sign/default", "vault-sign-off",
		map[string]any{"csr": string(csrPEM), "ttl": "15m"}, http.StatusOK)
	if !bytes.Contains(signed, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("Vault pki/sign while off has no certificate: %s", signed)
	}

	// Turned back on, the common-name mode generates and records it again.
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", token, "cpk-on",
		map[string]any{"enabled": true, "reason": "a legacy job still needs it"}); status != http.StatusOK {
		t.Fatalf("turn on = %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token, "pki-cn-on",
		map[string]any{"common_name": "keygen-on.example.test", "ttl_seconds": 900})
	if status != http.StatusCreated || !strings.Contains(string(body), "BEGIN PRIVATE KEY") {
		t.Fatalf("PKI secret by common name while on = %d %s", status, body)
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 1 {
		t.Fatalf("server-side key generations recorded = %d, want 1", got)
	}
}
