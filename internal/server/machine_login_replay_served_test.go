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
