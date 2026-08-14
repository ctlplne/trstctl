// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
)

func TestDynamicLeaseIdempotencyResultIsSealedAtRest(t *testing.T) {
	backend := newServedDynamicSecretBackend()
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		withDynamicSecretBackend(backend, time.Second),
	)
	registerServedTenant(t, h, "dynamic idempotency tenant")
	startServedExternalCADispatcher(t, h)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "dynamic-requester-a", "secrets:read", "secrets:write")
	otherToken := seedScopedTokenSubject(t, h.store, h.tenant, "dynamic-requester-b", "secrets:read", "secrets:write")
	request := map[string]any{"provider": "stub", "role": "readonly", "ttl_seconds": 60}
	const idempotencyKey = "dynamic-lease-sealed-result"

	status, first := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, idempotencyKey, request)
	if status != http.StatusCreated {
		t.Fatalf("first issue status=%d body=%s", status, first)
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, idempotencyKey, request)
	if status != http.StatusCreated || !bytes.Equal(first, replay) {
		t.Fatalf("idempotent replay status=%d body=%s, first=%s", status, replay, first)
	}
	if backend.n != 1 {
		t.Fatalf("provider generated %d credentials for one idempotency key", backend.n)
	}
	var response struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(first, &response); err != nil || response.Credential == "" {
		t.Fatalf("decode credential response err=%v body=%s", err, first)
	}
	status, changedTTL := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, idempotencyKey,
		map[string]any{"provider": "stub", "role": "readonly", "ttl_seconds": 120})
	if status != http.StatusConflict || bytes.Contains(changedTTL, []byte(response.Credential)) {
		t.Fatalf("same key/changed TTL status=%d body=%s, want credential-free 409", status, changedTTL)
	}
	status, changedCaller := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", otherToken, idempotencyKey, request)
	if status != http.StatusConflict || bytes.Contains(changedCaller, []byte(response.Credential)) {
		t.Fatalf("same key/changed principal status=%d body=%s, want credential-free 409", status, changedCaller)
	}
	if backend.n != 1 {
		t.Fatalf("collision requests generated %d credentials, want original one only", backend.n)
	}

	var stored []byte
	var requestBinding string
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT result, request_binding FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, h.tenant, idempotencyKey).Scan(&stored, &requestBinding)
	}); err != nil {
		t.Fatalf("load idempotency result: %v", err)
	}
	if requestBinding == "" {
		t.Fatal("credential-bearing idempotency row has no authenticated request binding")
	}
	if json.Valid(stored) || bytes.Contains(stored, []byte(response.Credential)) || bytes.Contains(stored, []byte("dynamic-secret")) {
		t.Fatalf("idempotency result persisted plaintext credential response: %q", stored)
	}
}

func TestDynamicLeaseRenewRevokeBindingsSurviveRecorderGC(t *testing.T) {
	provider := &issueOutboxProvider{name: "stub"}
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
		},
	)
	registerServedTenant(t, h, "dynamic lifecycle tenant")
	startServedExternalCADispatcher(t, h)
	caller := seedScopedTokenSubject(t, h.store, h.tenant, "dynamic-caller-a", "secrets:read", "secrets:write")
	other := seedScopedTokenSubject(t, h.store, h.tenant, "dynamic-caller-b", "secrets:read", "secrets:write")
	status, issued := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", caller, "durable-lifecycle-issue",
		map[string]any{"provider": "stub", "role": "reader", "ttl_seconds": 900})
	if status != http.StatusCreated {
		t.Fatalf("issue status=%d body=%s", status, issued)
	}
	var lease struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(issued, &lease); err != nil || lease.ID == "" {
		t.Fatalf("decode lease: %v body=%s", err, issued)
	}
	deleteRecorder := func(key string) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(context.Background(),
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, h.tenant, key); err != nil {
			t.Fatal(err)
		}
	}

	const renewKey = "durable-lifecycle-renew"
	renewCommand := map[string]any{"extend_seconds": 60}
	status, renewed := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", caller, renewKey, renewCommand)
	if status != http.StatusOK {
		t.Fatalf("renew status=%d body=%s", status, renewed)
	}
	deleteRecorder(renewKey)
	status, renewReplay := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", caller, renewKey, renewCommand)
	if status != http.StatusOK || !bytes.Equal(renewReplay, renewed) {
		t.Fatalf("renew replay status=%d body=%s original=%s", status, renewReplay, renewed)
	}
	deleteRecorder(renewKey)
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", other, renewKey, renewCommand)
	if status != http.StatusConflict {
		t.Fatalf("renew changed caller status=%d body=%s", status, body)
	}

	const revokeKey = "durable-lifecycle-revoke"
	status, revoked := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", caller, revokeKey, map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", status, revoked)
	}
	deleteRecorder(revokeKey)
	status, revokeReplay := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", caller, revokeKey, map[string]any{})
	if status != http.StatusOK || !bytes.Equal(revokeReplay, revoked) {
		t.Fatalf("revoke replay status=%d body=%s original=%s", status, revokeReplay, revoked)
	}
	deleteRecorder(revokeKey)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", other, revokeKey, map[string]any{})
	if status != http.StatusConflict {
		t.Fatalf("revoke changed caller status=%d body=%s", status, body)
	}
	deleteRecorder(revokeKey)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", caller, revokeKey, map[string]any{"extend_seconds": 1})
	if status != http.StatusConflict {
		t.Fatalf("cross-action raw key reuse status=%d body=%s", status, body)
	}
}
