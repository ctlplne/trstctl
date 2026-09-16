// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

func TestServedPKISecretCSRFirstAndLegacyEvidence(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant,
		"secrets:read", "secrets:write", "audit:read",
	)

	requesterKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer requesterKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(
		crypto.CertificateRequestTemplate{CommonName: "csr-secret.example.test"}, requesterKey,
	)
	if err != nil {
		t.Fatalf("create requester CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token,
		"pki-secret-csr-first", map[string]any{"csr_pem": string(csrPEM), "ttl_seconds": 900})
	if status != http.StatusCreated {
		t.Fatalf("CSR-first PKI secret = %d: %s", status, body)
	}
	if bytes.Contains(body, []byte(`"private_key"`)) || bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatalf("CSR-first response returned a private key: %s", body)
	}
	var csrResponse struct {
		Serial      string `json:"serial"`
		CommonName  string `json:"common_name"`
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &csrResponse); err != nil {
		t.Fatalf("decode CSR-first response: %v (%s)", err, body)
	}
	if csrResponse.Serial == "" || csrResponse.CommonName != "csr-secret.example.test" || csrResponse.Certificate == "" {
		t.Fatalf("CSR-first response is incomplete: %+v", csrResponse)
	}
	keyDER, err := requesterKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer wipeTestBytes(keyDER, keyPEM, csrPEM)
	if err := crypto.VerifyCertKeyMatchPEM([]byte(csrResponse.Certificate), keyPEM); err != nil {
		t.Fatalf("served certificate does not match requester CSR key: %v", err)
	}
	if eventCount(t, h.log, h.tenant, "issuance.server_side_keygen") != 0 {
		t.Fatal("CSR-first mode falsely recorded server-side key generation")
	}

	legacyKey := "pki-secret-legacy"
	legacyRequest := map[string]any{"common_name": "legacy-secret.example.test", "ttl_seconds": 900}
	status, legacyBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token, legacyKey, legacyRequest)
	if status != http.StatusCreated || !bytes.Contains(legacyBody, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("legacy PKI secret = %d: %s", status, legacyBody)
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 1 {
		t.Fatalf("legacy issuance deprecation count = %d, want 1", got)
	}

	// AN-5: replaying the exact request returns the sealed original response and
	// does not execute key generation or append a second deprecation receipt.
	status, replayBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token, legacyKey, legacyRequest)
	if status != http.StatusCreated || !bytes.Equal(legacyBody, replayBody) {
		t.Fatalf("legacy idempotent replay = %d body_equal=%t", status, bytes.Equal(legacyBody, replayBody))
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 1 {
		t.Fatalf("idempotent replay appended %d deprecation receipts, want 1 total", got)
	}
	status, conflictBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/pki", token,
		legacyKey, map[string]any{"csr_pem": string(csrPEM), "ttl_seconds": 900})
	if status != http.StatusConflict {
		t.Fatalf("same idempotency key with a different custody command = %d: %s", status, conflictBody)
	}
	if bytes.Contains(conflictBody, []byte("PRIVATE KEY")) || bytes.Contains(conflictBody, []byte(`"private_key"`)) {
		t.Fatalf("custody-binding conflict leaked the cached legacy key: %s", conflictBody)
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 1 {
		t.Fatalf("custody-binding conflict changed deprecation count to %d", got)
	}

	// A fresh production assembly over the same PostgreSQL/event/signer spine
	// must replay the sealed result. If it executes the callback again, this test
	// sees a second deprecation receipt and a different keypair response.
	restarted, err := Build(t.Context(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: h.kek, EnableSecretsAPI: true,
	})
	if err != nil {
		t.Fatalf("restart PKI-secret assembly: %v", err)
	}
	cleanupServedServer(t, restarted)
	restartedHTTP := httptest.NewServer(restarted.Handler())
	t.Cleanup(restartedHTTP.Close)
	restartedHarness := &servedHarness{
		srv: restarted, ts: restartedHTTP, store: h.store, log: h.log, tenant: h.tenant,
		signer: h.signer, authz: h.authz, caFile: h.caFile, kek: h.kek,
	}
	status, restartedBody := secretsReqKey(t, restartedHarness, http.MethodPost,
		"/api/v1/secrets/pki", token, legacyKey, legacyRequest)
	if status != http.StatusCreated || !bytes.Equal(restartedBody, legacyBody) {
		t.Fatalf("post-restart idempotent replay = %d body_equal=%t", status, bytes.Equal(restartedBody, legacyBody))
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 1 {
		t.Fatalf("post-restart replay changed deprecation count to %d", got)
	}
	foreignEvidence, err := json.Marshal(map[string]string{
		"identity_id": "", "name": "foreign-tenant.example.test",
		"detail":    "native_pki_secret: foreign tenant legacy choice",
		"successor": "supply csr_pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{
		Type: "issuance.server_side_keygen", TenantID: "22222222-2222-2222-2222-222222222222", Data: foreignEvidence,
	}); err != nil {
		t.Fatalf("append foreign-tenant isolation fixture: %v", err)
	}

	// The authenticated audit API is a fresh replay of the event log, not an
	// in-memory handler flag. This proves the same durable receipt is operator-readable.
	status, auditBody := secretsReq(t, h, http.MethodGet,
		"/api/v1/audit/events?type=issuance.server_side_keygen", token, nil)
	if status != http.StatusOK || !bytes.Contains(auditBody, []byte("legacy-secret.example.test")) ||
		!bytes.Contains(auditBody, []byte("native_pki_secret")) {
		t.Fatalf("durable legacy evidence is not audit-readable: status=%d body=%s", status, auditBody)
	}
	if bytes.Contains(auditBody, []byte("foreign-tenant.example.test")) {
		t.Fatalf("tenant-scoped audit read leaked foreign PKI custody evidence: %s", auditBody)
	}
}

func TestServedPKISecretRequiresExactlyOneCustodyMode(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:write")
	for name, tc := range map[string]struct {
		body       any
		wantDetail string
	}{
		"neither": {body: map[string]any{"ttl_seconds": 900}, wantDetail: "exactly one"},
		"both": {body: map[string]any{
			"common_name": "ambiguous.example.test",
			"csr_pem":     "-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----",
		}, wantDetail: "exactly one"},
		"malformed CSR": {body: map[string]any{
			"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----",
		}, wantDetail: "csr_pem is not PEM"},
	} {
		status, response := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/pki", token, tc.body)
		if status != http.StatusBadRequest || !bytes.Contains(response, []byte(tc.wantDetail)) {
			t.Fatalf("%s custody mode = %d: %s", name, status, response)
		}
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 0 {
		t.Fatalf("invalid custody requests recorded %d server-keygen events", got)
	}
}

func TestServedPKILegacyModeFailsClosedBeforeKeygenWhenEvidenceIsUnavailable(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:write")
	if err := h.log.Close(); err != nil {
		t.Fatalf("stop event log: %v", err)
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/pki", token, map[string]any{
		"common_name": "must-not-generate.example.test", "ttl_seconds": 900,
	})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("legacy issuance with unavailable evidence = %d: %s", status, body)
	}
	if bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, []byte(`"private_key"`)) {
		t.Fatalf("legacy issuance created or returned a key after evidence failure: %s", body)
	}
}

func TestServedVaultPKISignKeepsRequesterKeyAndIssueRecordsLegacyChoice(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant,
		"secrets:read", "secrets:write", "audit:read", "policy:read", "policy:write",
	)
	vaultServedRequest(t, h, token, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{
		"policy": `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`,
	}, http.StatusNoContent)

	requesterKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer requesterKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(
		crypto.CertificateRequestTemplate{CommonName: "vault-sign.example.test"}, requesterKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	defer wipeTestBytes(csrPEM)

	signRequest := map[string]any{
		"csr": string(csrPEM), "ttl": "15m",
	}
	signed := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/sign/default", "vault-pki-sign-csr", signRequest, http.StatusOK)
	if bytes.Contains(signed, []byte(`"private_key"`)) || bytes.Contains(signed, []byte("PRIVATE KEY")) {
		t.Fatalf("Vault sign response returned a private key: %s", signed)
	}
	if !bytes.Contains(signed, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("Vault sign response has no certificate: %s", signed)
	}
	replayed := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/sign/default", "vault-pki-sign-csr", signRequest, http.StatusOK)
	if !bytes.Equal(signed, replayed) {
		t.Fatalf("Vault sign idempotent replay changed the certificate: first=%s replay=%s", signed, replayed)
	}
	changedCSRDER, err := crypto.CreateCertificateRequest(
		crypto.CertificateRequestTemplate{CommonName: "changed.example.test"}, requesterKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	changedCSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: changedCSRDER})
	defer wipeTestBytes(changedCSRPEM)
	conflict := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/sign/default", "vault-pki-sign-csr", map[string]any{
		"csr": string(changedCSRPEM), "ttl": "15m",
	}, http.StatusConflict)
	if bytes.Contains(conflict, []byte("PRIVATE KEY")) || bytes.Contains(conflict, []byte(`"private_key"`)) {
		t.Fatalf("Vault sign idempotency conflict leaked key material: %s", conflict)
	}
	vaultServedRequest(t, h, token, http.MethodPost, "/v1/sys/mounts/application-pki", map[string]any{
		"type": "pki", "description": "AUD-24 mounted CSR signer",
	}, http.StatusNoContent)
	mountedSigned := vaultServedRequest(t, h, token, http.MethodPost, "/v1/application-pki/sign/default", map[string]any{
		"csr": string(csrPEM), "ttl": "15m",
	}, http.StatusOK)
	if bytes.Contains(mountedSigned, []byte(`"private_key"`)) || !bytes.Contains(mountedSigned, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("mounted Vault PKI sign custody response is wrong: %s", mountedSigned)
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 0 {
		t.Fatalf("Vault CSR sign paths falsely recorded %d server-side key generations", got)
	}

	legacyRequest := map[string]any{
		"common_name": "vault-issue.example.test", "ttl": "15m",
	}
	issued := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/issue/default", "vault-pki-issue-legacy", legacyRequest, http.StatusOK)
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 1 {
		t.Fatalf("Vault issue deprecation count = %d, want 1", got)
	}
	issuedReplay := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/issue/default", "vault-pki-issue-legacy", legacyRequest, http.StatusOK)
	if !bytes.Equal(issued, issuedReplay) {
		t.Fatalf("Vault issue idempotent replay changed the legacy keypair response")
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 1 {
		t.Fatalf("Vault issue replay appended %d deprecation receipts, want 1 total", got)
	}
	status, auditBody := secretsReq(t, h, http.MethodGet,
		"/api/v1/audit/events?type=issuance.server_side_keygen", token, nil)
	if status != http.StatusOK || !bytes.Contains(auditBody, []byte("vault_pki_issue")) {
		t.Fatalf("Vault legacy evidence is not audit-readable: status=%d body=%s", status, auditBody)
	}
}

func eventCount(t *testing.T, log *events.Log, tenantID, eventType string) int {
	t.Helper()
	count := 0
	if err := log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.TenantID == tenantID && event.Type == eventType {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func wipeTestBytes(values ...[]byte) func() {
	return func() {
		for _, value := range values {
			for i := range value {
				value[i] = 0
			}
		}
	}
}
