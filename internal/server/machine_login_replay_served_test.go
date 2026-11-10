// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// M4 prerequisite: an oidc machine login token is single-use. The served login
// accepts it once; the same token again — under a new idempotency key, so the
// login really runs — is refused; a fresh token logs in; and the durable record
// holds a digest, never the token.
func TestServedMachineLoginTokensAreSingleUseM4(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "ci-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
		Name: "oidc", TenantID: servedTestTenant, Issuer: "https://ci.example.test", Audience: "trstctl",
		JWKSJSON: string(jwks), Scopes: []string{"secrets:read"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	mint := func(jti string) string {
		t.Helper()
		tok, err := crypto.SignJWT(signer, "ci-key", map[string]any{
			"iss": "https://ci.example.test", "aud": "trstctl", "sub": "repo:payments:ref:main",
			"exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "jti": jti,
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	login := func(token, key string) (int, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"method": "oidc", "credential": token})
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", h.tenant)
		req.Header.Set("Idempotency-Key", key)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}

	token := mint("run-4711")
	if status, body := login(token, "m4-login-1"); status != http.StatusOK || !strings.Contains(body, "repo:payments:ref:main") {
		t.Fatalf("first login: HTTP %d %s", status, body)
	}
	// The same request again replays the recorded response (AN-5), not a login.
	if status, _ := login(token, "m4-login-1"); status != http.StatusOK {
		t.Fatalf("idempotent replay of the first login: HTTP %d", status)
	}
	if status, body := login(token, "m4-login-2"); status == http.StatusOK {
		t.Fatalf("the same token logged in twice: HTTP %d %s", status, body)
	}
	if status, body := login(mint("run-4712"), "m4-login-3"); status != http.StatusOK {
		t.Fatalf("a fresh token was refused: HTTP %d %s", status, body)
	}
	var rows int
	var leaked bool
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*), bool_or(key_digest LIKE '%' || $2 || '%') FROM machine_credential_replays WHERE tenant_id = $1 AND method = 'oidc'`,
		h.tenant, token[:40]).Scan(&rows, &leaked); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || leaked {
		t.Fatalf("single-use records = %d (token bytes stored: %v)", rows, leaked)
	}
	t.Logf("M4_REPLAY_OK records=%d", rows)
}

// A238-L8: a Kubernetes machine login token is single-use too, like an OIDC or
// JWT token and like the token exchange: logged in once, the same projected
// token is refused (any replica, after a restart), and a fresh one logs in. A
// method whose operator set allow_token_reuse — for a client such as the CSI
// secrets driver that presents the kubelet's token until it rotates — logs the
// same token in again.
func TestServedKubernetesMachineLoginIsSingleUseUnlessReuseIsAllowedA238L8(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "cluster-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.MachineAuthMethod{
		Name: "kubernetes", TenantID: servedTestTenant, Issuer: "https://kubernetes.default.svc.cluster.local", Audience: "trstctl",
		JWKSJSON: string(jwks), Scopes: []string{"secrets:read"}, AllowedNamespaces: []string{"payments"},
	}
	single, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{cfg})
	if err != nil {
		t.Fatal(err)
	}
	cfg.AllowTokenReuse = true
	reusable, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{cfg})
	if err != nil {
		t.Fatal(err)
	}
	current := single
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(func(tenantID string) []authmethod.Method { return current(tenantID) }, d.Store)
	})
	mint := func(pod string) string {
		t.Helper()
		now := time.Now()
		tok, err := crypto.SignJWT(signer, "cluster-key", map[string]any{
			"iss": "https://kubernetes.default.svc.cluster.local", "aud": []string{"trstctl"},
			"sub": "system:serviceaccount:payments:api", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
			"jti": "projected-" + pod,
			"kubernetes.io": map[string]any{
				"namespace":      "payments",
				"serviceaccount": map[string]any{"name": "api", "uid": "sa-uid-1"},
				"pod":            map[string]any{"name": pod, "uid": pod + "-uid"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	login := func(token, key string) (int, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"method": "kubernetes", "credential": token})
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", h.tenant)
		req.Header.Set("Idempotency-Key", key)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}

	// Served tests share one tenant, and other tests record kubernetes uses
	// too (the token exchange): count only this test's records.
	kubernetesUses := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT count(*) FROM machine_credential_replays WHERE tenant_id = $1 AND method = 'kubernetes'`, h.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := kubernetesUses()
	token := mint("api-7f9c")
	if status, body := login(token, "a238l8-login-1"); status != http.StatusOK || !strings.Contains(body, "system:serviceaccount:payments:api") {
		t.Fatalf("first kubernetes login: HTTP %d %s", status, body)
	}
	if status, body := login(token, "a238l8-login-2"); status == http.StatusOK {
		t.Fatalf("the same projected token logged in twice: HTTP %d %s", status, body)
	}
	if status, body := login(mint("api-8a1d"), "a238l8-login-3"); status != http.StatusOK {
		t.Fatalf("a fresh projected token was refused: HTTP %d %s", status, body)
	}

	current = reusable
	kubelet := mint("api-csi")
	for i, key := range []string{"a238l8-reuse-1", "a238l8-reuse-2", "a238l8-reuse-3"} {
		if status, body := login(kubelet, key); status != http.StatusOK {
			t.Fatalf("login %d of the same token under allow_token_reuse: HTTP %d %s", i+1, status, body)
		}
	}
	if rows := kubernetesUses() - before; rows != 2 {
		t.Fatalf("kubernetes single-use records = %d; want the two single-use logins, none for the reusable method", rows)
	}
}
