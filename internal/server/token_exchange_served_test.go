// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

const m4K8sIssuer = "https://kubernetes.default.svc.cluster.local"

// M4: a Kubernetes pod swaps its projected service-account token for a
// five-minute JWT-SVID scoped to what it asks for (RFC 8693). The JWT-SVID
// verifies offline against the published key; replaying the same subject token
// is refused; every exchange is recorded; refusals name the reason.
func TestServedTokenExchangeIssuesAFiveMinuteJWTSVIDM4(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "cluster-sa-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
		Name: "kubernetes", TenantID: servedTestTenant, Issuer: m4K8sIssuer, Audience: "trstctl",
		JWKSJSON: string(jwks), AllowedNamespaces: []string{"payments"}, Scopes: []string{"secrets:read", "certs:read"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
	}}, func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	projected := func(namespace, sa string) string {
		t.Helper()
		now := time.Now()
		tok, err := crypto.SignJWT(signer, "cluster-sa-key", map[string]any{
			"iss": m4K8sIssuer, "aud": []string{"trstctl"}, "sub": "system:serviceaccount:" + namespace + ":" + sa,
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
			"kubernetes.io": map[string]any{
				"namespace":      namespace,
				"serviceaccount": map[string]any{"name": sa, "uid": uuid.NewString()},
				"pod":            map[string]any{"name": sa + "-7d9f", "uid": uuid.NewString()},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	exchange := func(form url.Values) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", h.tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		body, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("token endpoint answered non-JSON (HTTP %d): %s", resp.StatusCode, body)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("token endpoint response is cacheable")
		}
		return resp.StatusCode, out
	}
	form := func(subject string, extra ...string) url.Values {
		v := url.Values{
			"grant_type":         {tokenExchangeGrant},
			"subject_token":      {subject},
			"subject_token_type": {tokenTypeJWT},
			"audience":           {"https://payments.internal"},
		}
		for i := 0; i+1 < len(extra); i += 2 {
			v.Set(extra[i], extra[i+1])
		}
		return v
	}

	subject := projected("payments", "api")
	status, out := exchange(form(subject, "scope", "secrets:read"))
	if status != http.StatusOK || out["issued_token_type"] != tokenTypeJWT || out["token_type"] != "Bearer" ||
		out["expires_in"] != float64(300) || out["scope"] != "secrets:read" {
		t.Fatalf("exchange: HTTP %d %v", status, out)
	}
	issued, _ := out["access_token"].(string)
	// Offline verification: the published key is all a relying party needs.
	resp, err := h.ts.Client().Get(h.ts.URL + "/oauth2/jwks")
	if err != nil {
		t.Fatal(err)
	}
	var published crypto.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&published); err != nil || len(published.Keys) == 0 {
		t.Fatalf("jwks: %v", err)
	}
	_ = resp.Body.Close()
	raw, err := crypto.VerifyJWTBytes([]byte(issued), published)
	if err != nil {
		t.Fatalf("the JWT-SVID does not verify against /oauth2/jwks: %v", err)
	}
	var claims struct {
		Sub   string   `json:"sub"`
		Aud   []string `json:"aud"`
		Iat   int64    `json:"iat"`
		Exp   int64    `json:"exp"`
		Scope string   `json:"scope"`
		JTI   string   `json:"jti"`
		Act   struct {
			Sub string `json:"sub"`
			Iss string `json:"iss"`
		} `json:"act"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "spiffe://served.test/ns/payments/sa/api" || len(claims.Aud) != 1 || claims.Aud[0] != "https://payments.internal" ||
		claims.Exp-claims.Iat != 300 || claims.Scope != "secrets:read" || claims.JTI == "" ||
		claims.Act.Sub != "system:serviceaccount:payments:api" || claims.Act.Iss != m4K8sIssuer {
		t.Fatalf("JWT-SVID claims = %+v", claims)
	}

	// Replaying the same subject token is refused.
	if status, out := exchange(form(subject)); status != http.StatusBadRequest || out["error"] != "invalid_grant" ||
		!strings.Contains(out["error_description"].(string), "already used") {
		t.Fatalf("replay: HTTP %d %v", status, out)
	}
	// A namespace the method does not allow is refused — and does not use up
	// the token, which a correct request then exchanges.
	other := projected("billing", "api")
	if status, out := exchange(form(other)); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("disallowed namespace: HTTP %d %v", status, out)
	}
	unknownIssuer, err := crypto.SignJWT(signer, "cluster-sa-key", map[string]any{
		"iss": "https://unknown.example.test", "aud": "trstctl", "sub": "system:serviceaccount:payments:api",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		form url.Values
		code string
	}{
		"no audience":      {url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {projected("payments", "api")}, "subject_token_type": {tokenTypeJWT}}, "invalid_target"},
		"ungranted scope":  {form(projected("payments", "api"), "scope", "keys:write"), "invalid_scope"},
		"other grant type": {form(projected("payments", "api"), "grant_type", "client_credentials"), "unsupported_grant_type"},
		"unknown issuer":   {form(unknownIssuer), "invalid_grant"},
	} {
		if status, out := exchange(tc.form); status != http.StatusBadRequest || out["error"] != tc.code {
			t.Fatalf("%s: HTTP %d %v, want %s", name, status, out, tc.code)
		}
	}

	// Every exchange is recorded; the subject token is not.
	var recorded int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM machine_credential_replays WHERE tenant_id = $1 AND method = 'kubernetes'`, h.tenant).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 {
		t.Fatalf("single-use records = %d, want 1 (refused requests must not consume)", recorded)
	}
	if !h.logContains(t, "spiffe://served.test/ns/payments/sa/api") || h.logContains(t, subject) {
		t.Fatal("token.exchanged missing from the event log, or the subject token reached it")
	}
	t.Logf("M4_OK sub=%s scope=%s ttl=%ds", claims.Sub, claims.Scope, claims.Exp-claims.Iat)
}
