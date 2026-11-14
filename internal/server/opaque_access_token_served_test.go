// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// M4-L3 part 2: for an audience in protocols.spiffe.opaque_token_audiences the
// exchange's access token is opaque — the claims sealed under the tenant's own
// key, nothing stored — and the resource server introspects it (RFC 7662) with
// its own API token (issuers:read): active, with subject, client, audience,
// scope, issuer and expiry. The same token is inactive to another tenant,
// altered, or expired; a caller without issuers:read is refused; a request
// mixing an opaque audience with another is refused; an audience not listed
// still gets an RFC 9068 JWT; the issuer view lists the opaque audiences and
// where to introspect.
func TestServedOpaqueAccessTokenIsIntrospectedM4L3(t *testing.T) {
	const issuerBase = "https://issuer-m4l3o.trstctl.example.test"
	const legacy = "https://legacy-m4l3.internal"
	tenant := uuid.NewSHA1(uuid.NameSpaceOID, []byte("m4l3-opaque-tenant")).String()
	other := uuid.NewSHA1(uuid.NameSpaceOID, []byte("m4l3-opaque-other-tenant")).String()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "m4l3o-sa-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	const k8sIssuer = m4K8sIssuer + "/m4l3o"
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
		Name: "kubernetes", TenantID: tenant, Issuer: k8sIssuer, Audience: "trstctl", JWKSJSON: string(jwks),
		AllowedNamespaces: []string{"payments"}, Scopes: []string{"certs:read", "secrets:read"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	protocols := config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: tenant, TrustDomain: "served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		OIDCIssuerURL: issuerBase, OpaqueTokenAudiences: []string{legacy},
	}}
	if errs := protocols.ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("the protocols as configured: %v", errs)
	}
	h := newOperatingServedHarness(t, protocols, withProtectedSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenantID(t, h, tenant, "M4-L3 opaque tenant")
	registerServedTenantID(t, h, other, "M4-L3 opaque other tenant")
	resourceServer := seedScopedToken(t, h.store, tenant, "issuers:read")
	unprivileged := seedScopedToken(t, h.store, tenant, "certs:read")
	otherServer := seedScopedToken(t, h.store, other, "issuers:read")

	exchange := func(audience ...string) (int, map[string]any) {
		t.Helper()
		now := time.Now()
		subject, err := crypto.SignJWT(signer, "m4l3o-sa-key", map[string]any{
			"iss": k8sIssuer, "aud": []string{"trstctl"}, "sub": "system:serviceaccount:payments:api",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
			"kubernetes.io": map[string]any{"namespace": "payments",
				"serviceaccount": map[string]any{"name": "api", "uid": uuid.NewString()},
				"pod":            map[string]any{"name": "api-7d9f", "uid": uuid.NewString()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {subject}, "subject_token_type": {tokenTypeJWT},
			"requested_token_type": {tokenTypeAccessToken}, "scope": {"certs:read"}, "audience": audience}
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	introspect := func(apiToken, token string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/workloads/tokens/introspect",
			strings.NewReader(url.Values{"token": {token}, "token_type_hint": {"access_token"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+apiToken)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		if resp.StatusCode == http.StatusOK && resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("an introspection answer is cacheable")
		}
		return resp.StatusCode, out
	}

	status, out := exchange(legacy)
	opaque, _ := out["access_token"].(string)
	if status != http.StatusOK || out["issued_token_type"] != tokenTypeAccessToken || !strings.HasPrefix(opaque, opaqueAccessTokenPrefix) || strings.Count(opaque, ".") != 0 {
		t.Fatalf("opaque exchange: HTTP %d %v; want an opaque access token", status, redactedExchange(out))
	}
	const workload = "spiffe://served.test/ns/payments/sa/api"
	status, got := introspect(resourceServer, opaque)
	aud, _ := got["aud"].([]any)
	if status != http.StatusOK || got["active"] != true || got["sub"] != workload || got["client_id"] != workload ||
		got["iss"] != issuerBase+"/oidc/"+tenant || got["scope"] != "certs:read" || len(aud) != 1 || aud[0] != legacy ||
		got["token_type"] != "Bearer" || got["jti"] == "" || got["exp"].(float64)-got["iat"].(float64) != 300 {
		t.Fatalf("introspection: HTTP %d %v", status, got)
	}
	inactive := func(name string, status int, got map[string]any) {
		t.Helper()
		if status != http.StatusOK || got["active"] != false || len(got) != 1 {
			t.Fatalf("%s: HTTP %d %v; want only active false", name, status, got)
		}
	}
	status, got = introspect(otherServer, opaque)
	inactive("another tenant's resource server", status, got)
	altered := []byte(opaque)
	altered[len(altered)-3] ^= 0x01
	if altered[len(altered)-3] == '.' {
		altered[len(altered)-3] = 'A'
	}
	status, got = introspect(resourceServer, string(altered))
	inactive("an altered token", status, got)
	sp := h.srv.spiffeForExchange()
	expired, err := h.srv.sealOpaqueAccessToken(t.Context(), sp, tenant, opaqueAccessTokenClaims{
		Iss: issuerBase + "/oidc/" + tenant, Sub: workload, ClientID: workload, Aud: []string{legacy},
		Iat: time.Now().Add(-10 * time.Minute).Unix(), Exp: time.Now().Add(-5 * time.Minute).Unix(), JTI: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	status, got = introspect(resourceServer, expired)
	inactive("an expired token", status, got)
	status, got = introspect(resourceServer, "trsto_"+base64.RawURLEncoding.EncodeToString([]byte("not sealed")))
	inactive("a value that is not a token", status, got)
	if status, got := introspect(unprivileged, opaque); status != http.StatusForbidden {
		t.Fatalf("a caller without issuers:read: HTTP %d %v", status, got)
	}

	if status, out := exchange(legacy, "https://payments.internal"); status != http.StatusBadRequest || out["error"] != "invalid_target" {
		t.Fatalf("an opaque audience mixed with another: HTTP %d %v", status, out)
	}
	status, out = exchange("https://payments.internal")
	if jwt, _ := out["access_token"].(string); status != http.StatusOK || strings.Count(jwt, ".") != 2 || strings.HasPrefix(jwt, opaqueAccessTokenPrefix) {
		t.Fatalf("an audience not listed: HTTP %d %v; want an RFC 9068 JWT", status, redactedExchange(out))
	}
	info, published := h.srv.OIDCIssuerFor(httptest.NewRequest(http.MethodGet, "/api/v1/workloads/oidc-issuer", nil), tenant)
	if !published || len(info.OpaqueTokenAudiences) != 1 || info.OpaqueTokenAudiences[0] != legacy || info.IntrospectionEndpoint != "/api/v1/workloads/tokens/introspect" {
		t.Fatalf("the issuer view = %+v (published %v)", info, published)
	}
	if !h.logContains(t, `"opaque":true`) || h.logContains(t, opaque) {
		t.Fatal("token.exchanged does not say the token was opaque, or the token reached the log")
	}
	t.Logf("M4L3_OPAQUE_OK prefix=%s introspected_sub=%s", opaqueAccessTokenPrefix, workload)
}
