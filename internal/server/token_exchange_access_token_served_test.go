// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
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

// M4-L3: a workload whose resource server accepts OAuth access tokens asks
// the exchange for one (requested_token_type …:access_token) and receives an
// RFC 9068 JWT access token: header typ at+jwt, iss the tenant's published
// issuer, sub and client_id the workload's SPIFFE ID, the requested audience
// and scope, five minutes, verifiable against the issuer's key set. Without
// a requested type the exchange still issues a JWT-SVID; a type it does not
// issue is refused; the recorded exchange names the type it issued.
func TestServedTokenExchangeIssuesAnRFC9068AccessTokenM4L3(t *testing.T) {
	const issuerBase = "https://issuer-m4l3.trstctl.example.test"
	// Its own tenant, so its single-use records never meet another test's.
	tenant := uuid.NewSHA1(uuid.NameSpaceOID, []byte("m4l3-exchange-tenant")).String()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "m4l3-sa-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	const k8sIssuer = m4K8sIssuer + "/m4l3"
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
		Name: "kubernetes", TenantID: tenant, Issuer: k8sIssuer, Audience: "trstctl", JWKSJSON: string(jwks),
		AllowedNamespaces: []string{"payments"}, Scopes: []string{"certs:read", "secrets:read"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: tenant, TrustDomain: "served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		OIDCIssuerURL: issuerBase,
	}}, func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenantID(t, h, tenant, "M4-L3 exchange tenant")
	projected := func() string {
		t.Helper()
		now := time.Now()
		tok, err := crypto.SignJWT(signer, "m4l3-sa-key", map[string]any{
			"iss": k8sIssuer, "aud": []string{"trstctl"}, "sub": "system:serviceaccount:payments:api",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
			"kubernetes.io": map[string]any{"namespace": "payments",
				"serviceaccount": map[string]any{"name": "api", "uid": uuid.NewString()},
				"pod":            map[string]any{"name": "api-7d9f", "uid": uuid.NewString()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	exchange := func(extra ...string) (int, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {projected()},
			"subject_token_type": {tokenTypeJWT}, "audience": {"https://payments.internal"}}
		for i := 0; i+1 < len(extra); i += 2 {
			form.Set(extra[i], extra[i+1])
		}
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("token endpoint answered non-JSON (HTTP %d)", resp.StatusCode)
		}
		return resp.StatusCode, out
	}
	typOf := func(token string) string {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(token, ".", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		var header struct {
			Typ string `json:"typ"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatal(err)
		}
		return header.Typ
	}
	resp, err := h.ts.Client().Get(h.ts.URL + "/oidc/" + tenant + "/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	var published crypto.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&published); err != nil || len(published.Keys) == 0 {
		t.Fatalf("the issuer's key set: %v", err)
	}
	_ = resp.Body.Close()

	status, out := exchange("requested_token_type", tokenTypeAccessToken, "scope", "certs:read")
	if status != http.StatusOK || out["issued_token_type"] != tokenTypeAccessToken || out["token_type"] != "Bearer" ||
		out["expires_in"] != float64(300) || out["scope"] != "certs:read" {
		t.Fatalf("access token exchange: HTTP %d %v", status, redactedExchange(out))
	}
	accessToken, _ := out["access_token"].(string)
	if typOf(accessToken) != "at+jwt" {
		t.Fatalf("access token typ = %q; want at+jwt", typOf(accessToken))
	}
	raw, err := crypto.VerifyJWTBytes([]byte(accessToken), published)
	if err != nil {
		t.Fatalf("the access token does not verify against the issuer's key set: %v", err)
	}
	var claims struct {
		Iss      string   `json:"iss"`
		Sub      string   `json:"sub"`
		ClientID string   `json:"client_id"`
		Aud      []string `json:"aud"`
		Iat      int64    `json:"iat"`
		Exp      int64    `json:"exp"`
		Scope    string   `json:"scope"`
		JTI      string   `json:"jti"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	const workload = "spiffe://served.test/ns/payments/sa/api"
	if claims.Iss != issuerBase+"/oidc/"+tenant || claims.Sub != workload || claims.ClientID != workload ||
		len(claims.Aud) != 1 || claims.Aud[0] != "https://payments.internal" || claims.Exp-claims.Iat != 300 ||
		claims.Scope != "certs:read" || claims.JTI == "" {
		t.Fatalf("access token claims = %+v", claims)
	}

	status, out = exchange()
	if svid, _ := out["access_token"].(string); status != http.StatusOK || out["issued_token_type"] != tokenTypeJWT || typOf(svid) != "JWT" {
		t.Fatalf("the default exchange: HTTP %d %v; want a JWT-SVID", status, redactedExchange(out))
	}
	if status, out := exchange("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"); status != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Fatalf("a type the exchange does not issue: HTTP %d %v", status, out)
	}
	if !h.logContains(t, `"issued_token_type":"`+tokenTypeAccessToken+`"`) || !h.logContains(t, claims.JTI) || h.logContains(t, accessToken) {
		t.Fatal("token.exchanged does not name the access token it issued, or the token reached the log")
	}
	t.Logf("M4L3_ACCESS_TOKEN_OK typ=at+jwt iss=%s client_id=%s", claims.Iss, claims.ClientID)
}

// redactedExchange is a token endpoint answer without its token, for a
// failure message.
func redactedExchange(out map[string]any) map[string]any {
	copied := make(map[string]any, len(out))
	for k, v := range out {
		if k == "access_token" {
			v = "[redacted]"
		}
		copied[k] = v
	}
	return copied
}
