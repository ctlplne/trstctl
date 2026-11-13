// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// M4-L2: each tenant holds at most secrets.machine_auth_single_use_limit live
// single-use records. With a limit of two, an OIDC login and a token exchange
// take them; a third token is refused with 429 and a Retry-After — at the
// login API and at the token endpoint alike — and is not used up; a replayed
// token is still refused as a replay; and once the oldest record expires the
// refused token logs in.
func TestServedMachineLoginAndExchangeHonorTheSingleUseLimitM4L2(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "m4l2-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	const ciIssuer = "https://ci-m4l2.example.test"
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{
		{Name: "oidc", TenantID: servedTestTenant, Issuer: ciIssuer, Audience: "trstctl", JWKSJSON: string(jwks), Scopes: []string{"secrets:read"}},
		{Name: "kubernetes", TenantID: servedTestTenant, Issuer: m4K8sIssuer, Audience: "trstctl", JWKSJSON: string(jwks),
			AllowedNamespaces: []string{"m4l2"}, Scopes: []string{"secrets:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
	}}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuardLimit(methods, d.Store, 2)
		d.MachineCredentialUseLimit = 2
	})
	// Served tests share one tenant and its single-use records: start empty
	// and leave nothing behind.
	clearRecords := func() {
		if _, err := h.store.SystemPool().Exec(t.Context(), `DELETE FROM machine_credential_replays WHERE tenant_id = $1`, h.tenant); err != nil {
			t.Fatal(err)
		}
	}
	clearRecords()
	t.Cleanup(func() {
		// t.Context() is already canceled when cleanups run.
		_, _ = h.store.SystemPool().Exec(context.Background(), `DELETE FROM machine_credential_replays WHERE tenant_id = $1`, h.tenant)
	})
	mint := func(claims map[string]any) string {
		t.Helper()
		now := time.Now()
		claims["aud"], claims["iat"], claims["exp"], claims["jti"] = "trstctl", now.Unix(), now.Add(10*time.Minute).Unix(), uuid.NewString()
		tok, err := crypto.SignJWT(signer, "m4l2-key", claims)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	ciToken := func() string { return mint(map[string]any{"iss": ciIssuer, "sub": "repo:m4l2:ref:main"}) }
	podToken := func() string {
		return mint(map[string]any{"iss": m4K8sIssuer, "sub": "system:serviceaccount:m4l2:api",
			"kubernetes.io": map[string]any{"namespace": "m4l2", "serviceaccount": map[string]any{"name": "api", "uid": uuid.NewString()}}})
	}
	login := func(token, key string) (int, string, string) {
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
		return resp.StatusCode, resp.Header.Get("Retry-After"), string(data)
	}
	exchange := func(subject string) (int, string, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {subject},
			"subject_token_type": {tokenTypeJWT}, "audience": {"https://m4l2.internal"}}
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", h.tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, resp.Header.Get("Retry-After"), out
	}
	waitSeconds := func(header string) int {
		n, err := strconv.Atoi(header)
		if err != nil {
			return -1
		}
		return n
	}

	first := ciToken()
	if status, _, body := login(first, "m4l2-login-1"); status != http.StatusOK {
		t.Fatalf("first login: HTTP %d %s", status, body)
	}
	if status, _, out := exchange(podToken()); status != http.StatusOK {
		t.Fatalf("first exchange: HTTP %d %v", status, out)
	}
	refused := ciToken()
	status, retry, body := login(refused, "m4l2-login-2")
	if status != http.StatusTooManyRequests || waitSeconds(retry) < 1 || waitSeconds(retry) > 601 || !strings.Contains(body, "single-use login records are at their limit") {
		if status == http.StatusOK {
			body = "(a session was issued; its token is not printed)"
		}
		t.Fatalf("a login past the limit: HTTP %d Retry-After %q %s; want 429 with the wait", status, retry, body)
	}
	status, retry, out := exchange(podToken())
	if status != http.StatusTooManyRequests || waitSeconds(retry) < 1 || out["error"] != "temporarily_unavailable" {
		t.Fatalf("an exchange past the limit: HTTP %d Retry-After %q %v; want 429 with the wait", status, retry, out)
	}
	if status, _, _ := login(first, "m4l2-login-3"); status != http.StatusUnauthorized {
		t.Fatalf("a replay at the limit: HTTP %d; want the replay refused as one", status)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE machine_credential_replays SET expires_at = now() - interval '1 second'
		WHERE tenant_id = $1 AND method = 'oidc'`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if status, _, body := login(refused, "m4l2-login-4"); status != http.StatusOK {
		t.Fatalf("the refused token once room was freed: HTTP %d %s; want it not used up", status, body)
	}
	t.Logf("M4L2_SINGLE_USE_LIMIT_OK limit=2 exchange_retry_after=%ss", retry)
}
