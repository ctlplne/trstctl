//go:build trstctl_dodproof

// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const dodVaultCompatTenant = "d0d00000-0000-4000-8000-000000000501"

var dodVaultRequestSequence atomic.Uint64

// TestDODVaultCompatProductionAssembly passes untouched buildRunDeps output to
// Build, drives the resulting shipped handler, and sends raw Vault response
// bytes to a separately launched compatibility verifier before sealing evidence.
func TestDODVaultCompatProductionAssembly(t *testing.T) {
	_ = dodRuntimeSelection(t, "secrets_residuals.vault_shim_acl_transit")
	external := proof.StartCommand(t, "secrets_residuals.vault_shim_acl_transit")
	verifierEndpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Secrets.KEKFile = filepath.Join(dir, "secrets-kek.bin")
	cfg.Audit.SigningKeyFile = filepath.Join(dir, "audit-signing-key.pem")
	cfg.Signer.KeyStoreDir = filepath.Join(dir, "signer-keys")
	cfg.CA.CertFile = filepath.Join(dir, "issuing-ca.crt")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Vault production config: %v", err)
	}

	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(dir, "nats")})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	dodRegisterVaultCompatTenant(t, ctx, log, st)
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("load run secrets: %v", err)
	}
	defer runSecrets.Close()
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	signer := dodStartAuthorizedSoftwareSignerProcess(t, dir)
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	defer func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()
	token := dodSeedAPIToken(t, ctx, st, dodVaultCompatTenant, "dod-vault-client", []string{
		string(authz.PolicyRead), string(authz.PolicyWrite), string(authz.KeysRead), string(authz.KeysWrite),
		string(authz.SecretsRead), string(authz.SecretsWrite),
	})
	allowAll := `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`
	dodVaultRequest(t, srv, token, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{"policy": allowAll}, http.StatusNoContent)
	aclAuthored := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/sys/policies/acl/api-token", nil, http.StatusOK)
	dodVaultRequest(t, srv, token, http.MethodPut, "/v1/sys/policies/acl/lifecycle", map[string]any{"policy": allowAll}, http.StatusNoContent)
	aclListBeforeDelete := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/sys/policies/acl", nil, http.StatusOK)
	aclRead := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/sys/policies/acl/lifecycle", nil, http.StatusOK)
	dodVaultRequest(t, srv, token, http.MethodDelete, "/v1/sys/policies/acl/lifecycle", nil, http.StatusNoContent)
	aclListAfterDelete := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/sys/policies/acl", nil, http.StatusOK)
	for path, kind := range map[string]string{"application-secrets": "kv-v2", "application-transit": "transit", "application-pki": "pki"} {
		dodVaultRequest(t, srv, token, http.MethodPost, "/v1/sys/mounts/"+path, map[string]any{
			"type": kind, "description": "DoD compatibility mount", "config": map[string]any{}, "options": map[string]string{"version": "2"},
		}, http.StatusNoContent)
	}

	mountRequest, err := http.NewRequest(http.MethodGet, "/v1/sys/mounts", nil)
	if err != nil {
		t.Fatal(err)
	}
	mountRequest.Header.Set("X-Vault-Token", token)
	session := proof.Start(t, "secrets_residuals.vault_shim_acl_transit", srv.Handler(), mountRequest)
	if session.StatusCode() != http.StatusOK {
		t.Fatalf("mount list status=%d body=%s", session.StatusCode(), session.ResponseBody())
	}
	discovery := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/sys/internal/ui/mounts/application-transit/encrypt/app", nil, http.StatusOK)
	dodVaultRequest(t, srv, token, http.MethodPut, "/v1/secret/data/application", map[string]any{"data": map[string]string{"source": "builtin"}}, http.StatusOK)
	dodVaultRequest(t, srv, token, http.MethodPut, "/v1/application-secrets/data/application", map[string]any{"data": map[string]string{"source": "mounted"}}, http.StatusOK)
	builtinKV := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/secret/data/application", nil, http.StatusOK)
	mountedKV := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/application-secrets/data/application", nil, http.StatusOK)

	dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/keys/app", map[string]any{"type": "aes256-gcm96"}, http.StatusNoContent)
	plaintext := []byte("dod-vault-transit-production-assembly")
	defer secret.Wipe(plaintext)
	plaintextB64 := base64.StdEncoding.EncodeToString(plaintext)
	encryptedV1 := dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/encrypt/app", map[string]any{"plaintext": plaintextB64}, http.StatusOK)
	ciphertextV1 := dodVaultResponseDataString(t, encryptedV1, "ciphertext")
	dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/keys/app/rotate", nil, http.StatusNoContent)
	encryptedV2 := dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/encrypt/app", map[string]any{"plaintext": plaintextB64}, http.StatusOK)
	ciphertextV2 := dodVaultResponseDataString(t, encryptedV2, "ciphertext")
	if ciphertextV1 == ciphertextV2 {
		t.Fatal("rotated transit key returned the original ciphertext")
	}
	rewrapped := dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/rewrap/app", map[string]any{"ciphertext": ciphertextV1}, http.StatusOK)
	rewrappedCiphertext := dodVaultResponseDataString(t, rewrapped, "ciphertext")
	decryptedRewrapped := dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/decrypt/app", map[string]any{"ciphertext": rewrappedCiphertext}, http.StatusOK)

	dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/keys/mac", map[string]any{"type": "hmac-sha2-256"}, http.StatusNoContent)
	hmacResponse := dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/hmac/mac", map[string]any{"input": plaintextB64}, http.StatusOK)
	dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/keys/signer", map[string]any{"type": "ecdsa-p256"}, http.StatusNoContent)
	signed := dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/sign/signer", map[string]any{"input": plaintextB64}, http.StatusOK)
	signature := dodVaultResponseDataString(t, signed, "signature")
	verified := dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-transit/verify/signer", map[string]any{"input": plaintextB64, "signature": signature}, http.StatusOK)
	pki := dodVaultRequest(t, srv, token, http.MethodPost, "/v1/application-pki/issue/default", map[string]any{
		"common_name": "svc.dod-vault.test", "ttl": "15m",
	}, http.StatusOK)
	dodVaultRequest(t, srv, token, http.MethodDelete, "/v1/sys/mounts/application-secrets", nil, http.StatusNoContent)
	mountsAfterDisable := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/sys/mounts", nil, http.StatusOK)
	readOnly := `path "secret/data/*" { capabilities = ["read"] }`
	dodVaultRequest(t, srv, token, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{"policy": readOnly}, http.StatusNoContent)
	aclDenied := dodVaultRequest(t, srv, token, http.MethodGet, "/v1/sys/mounts", nil, http.StatusForbidden)

	verification := map[string]any{
		"protocol": "vault-openbao-v1", "plaintext_b64": plaintextB64,
		"acl_authored":           base64.StdEncoding.EncodeToString(aclAuthored),
		"acl_list_before_delete": base64.StdEncoding.EncodeToString(aclListBeforeDelete),
		"acl_read":               base64.StdEncoding.EncodeToString(aclRead),
		"acl_list_after_delete":  base64.StdEncoding.EncodeToString(aclListAfterDelete),
		"mounts":                 base64.StdEncoding.EncodeToString(session.ResponseBody()),
		"mounts_after_disable":   base64.StdEncoding.EncodeToString(mountsAfterDisable),
		"discovery":              base64.StdEncoding.EncodeToString(discovery),
		"builtin_kv":             base64.StdEncoding.EncodeToString(builtinKV),
		"mounted_kv":             base64.StdEncoding.EncodeToString(mountedKV),
		"encrypt_v1":             base64.StdEncoding.EncodeToString(encryptedV1),
		"encrypt_v2":             base64.StdEncoding.EncodeToString(encryptedV2),
		"rewrap":                 base64.StdEncoding.EncodeToString(rewrapped),
		"decrypt_rewrapped":      base64.StdEncoding.EncodeToString(decryptedRewrapped),
		"hmac":                   base64.StdEncoding.EncodeToString(hmacResponse),
		"sign":                   base64.StdEncoding.EncodeToString(signed),
		"verify":                 base64.StdEncoding.EncodeToString(verified),
		"pki":                    base64.StdEncoding.EncodeToString(pki),
		"acl_denied":             base64.StdEncoding.EncodeToString(aclDenied),
	}
	verifierReadback := dodVaultVerifyTranscript(t, verifierEndpoint, verification)
	executionReceipt := external.StopAndReceipt()
	transcript := bytes.Join([][]byte{
		aclAuthored, aclListBeforeDelete, aclRead, aclListAfterDelete,
		session.ResponseBody(), mountsAfterDisable, discovery, builtinKV, mountedKV,
		encryptedV1, encryptedV2, rewrapped, decryptedRewrapped, hmacResponse, signed, verified, pki, aclDenied,
	}, nil)
	session.Complete(proof.IndependentInterop(proof.IndependentInteropProbe{
		ClientIdentity: []byte("Vault/OpenBao v1 independent response verifier"),
		Transcript:     transcript, IndependentVerifier: verifierReadback, ExecutionReceipt: executionReceipt,
	}))
}

func dodRegisterVaultCompatTenant(t *testing.T, ctx context.Context, log *events.Log, st *store.Store) {
	t.Helper()
	service := app.New(log, st, nil)
	defer service.Close()
	if err := service.RegisterTenant(ctx, dodVaultCompatTenant, "DoD Vault compatibility",
		"dod-vault-compat-register-tenant"); err != nil {
		t.Fatalf("register Vault-compatible proof tenant through event spine: %v", err)
	}
}

func dodVaultResponseDataString(t *testing.T, body []byte, field string) string {
	t.Helper()
	var response struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode Vault response: %v: %s", err, body)
	}
	var value string
	if err := json.Unmarshal(response.Data[field], &value); err != nil || value == "" {
		t.Fatalf("decode Vault data.%s: %v: %s", field, err, body)
	}
	return value
}

func dodVaultRequest(t *testing.T, srv *Server, token, method, path string, body any, want int) []byte {
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Vault-Token", token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "dod-vault-"+strconv.FormatUint(dodVaultRequestSequence.Add(1), 10))
	response := &dodHTTPRecorder{header: make(http.Header), status: http.StatusOK}
	srv.Handler().ServeHTTP(response, request)
	if response.status != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.status, want, response.body.Bytes())
	}
	return append([]byte(nil), response.body.Bytes()...)
}

func dodVaultVerifyTranscript(t *testing.T, endpoint string, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(endpoint+"/v1/verify", "application/json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("Vault independent verifier: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK || len(body) < 16 {
		t.Fatalf("Vault independent verifier status=%d bytes=%d err=%v body=%s", response.StatusCode, len(body), err, body)
	}
	return body
}
