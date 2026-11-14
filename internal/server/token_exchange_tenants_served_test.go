// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
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

// M4-L5: the token exchange serves more tenants than the SPIFFE surface's own.
// A tenant in protocols.spiffe.exchange_tenants exchanges in its own trust
// domain with its own JWT key in the signer: its JWT-SVID names
// spiffe://<its trust domain>/… and its published issuer, verifies against
// its own key set and not against the surface tenant's (and the surface
// tenant's tokens not against its), it rotates its key without touching the
// other ring, and a tenant in neither is refused.
func TestServedTokenExchangeServesAnotherTenantInItsOwnTrustDomainM4L5(t *testing.T) {
	const issuerBase = "https://issuer-m4l5.trstctl.example.test"
	main := uuid.NewSHA1(uuid.NameSpaceOID, []byte("m4l5-surface-tenant")).String()
	second := uuid.NewSHA1(uuid.NameSpaceOID, []byte("m4l5-exchange-tenant")).String()
	unserved := uuid.NewSHA1(uuid.NameSpaceOID, []byte("m4l5-unserved-tenant")).String()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "m4l5-sa-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	issuerOf := map[string]string{main: m4K8sIssuer + "/m4l5-a", second: m4K8sIssuer + "/m4l5-b", unserved: m4K8sIssuer + "/m4l5-c"}
	var methodCfgs []config.MachineAuthMethod
	for tenant, iss := range issuerOf {
		methodCfgs = append(methodCfgs, config.MachineAuthMethod{Name: "kubernetes", TenantID: tenant, Issuer: iss, Audience: "trstctl",
			JWKSJSON: string(jwks), AllowedNamespaces: []string{"payments"}, Scopes: []string{"certs:read"}})
	}
	methods, err := machineAuthMethodsFromConfig(methodCfgs)
	if err != nil {
		t.Fatal(err)
	}
	protocols := config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: main, TrustDomain: "m4l5.served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		OIDCIssuerURL:   issuerBase,
		ExchangeTenants: []config.SPIFFEExchangeTenant{{TenantID: second, TrustDomain: "second.m4l5.served.test"}},
	}}
	if errs := protocols.ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("the protocols as configured: %v", errs)
	}
	h := newOperatingServedHarness(t, protocols, func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenantID(t, h, main, "M4-L5 surface tenant")
	registerServedTenantID(t, h, second, "M4-L5 exchange tenant")
	registerServedTenantID(t, h, unserved, "M4-L5 unserved tenant")

	exchange := func(tenant string) (int, map[string]any) {
		t.Helper()
		now := time.Now()
		subject, err := crypto.SignJWT(signer, "m4l5-sa-key", map[string]any{
			"iss": issuerOf[tenant], "aud": []string{"trstctl"}, "sub": "system:serviceaccount:payments:api",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
			"kubernetes.io": map[string]any{"namespace": "payments",
				"serviceaccount": map[string]any{"name": "api", "uid": uuid.NewString()},
				"pod":            map[string]any{"name": "api-7d9f", "uid": uuid.NewString()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {subject},
			"subject_token_type": {tokenTypeJWT}, "audience": {"https://payments.internal"}}
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
	keySet := func(path string) crypto.JWKS {
		t.Helper()
		resp, err := h.ts.Client().Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var set crypto.JWKS
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&set) != nil || len(set.Keys) == 0 {
			t.Fatalf("key set %s: HTTP %d", path, resp.StatusCode)
		}
		return set
	}
	claimsOf := func(token string, set crypto.JWKS) (map[string]any, error) {
		raw, err := crypto.VerifyJWTBytes([]byte(token), set)
		if err != nil {
			return nil, err
		}
		var claims map[string]any
		return claims, json.Unmarshal(raw, &claims)
	}
	mainKeys, secondKeys := keySet("/oidc/"+main+"/jwks.json"), keySet("/oidc/"+second+"/jwks.json")

	status, out := exchange(second)
	secondToken, _ := out["access_token"].(string)
	if status != http.StatusOK {
		t.Fatalf("the exchange tenant's exchange: HTTP %d %v", status, redactedExchange(out))
	}
	claims, err := claimsOf(secondToken, secondKeys)
	if err != nil || claims["sub"] != "spiffe://second.m4l5.served.test/ns/payments/sa/api" || claims["iss"] != issuerBase+"/oidc/"+second {
		t.Fatalf("the exchange tenant's JWT-SVID = %v %v", claims, err)
	}
	if _, err := claimsOf(secondToken, mainKeys); err == nil {
		t.Fatal("the exchange tenant's token verifies against the surface tenant's key set")
	}
	if _, err := claimsOf(secondToken, keySet("/oauth2/jwks?tenant_id="+second)); err != nil {
		t.Fatalf("the exchange tenant's token does not verify against /oauth2/jwks?tenant_id: %v", err)
	}
	status, out = exchange(main)
	mainToken, _ := out["access_token"].(string)
	if claims, err := claimsOf(mainToken, keySet("/oauth2/jwks")); status != http.StatusOK || err != nil || claims["sub"] != "spiffe://m4l5.served.test/ns/payments/sa/api" {
		t.Fatalf("the surface tenant's exchange: HTTP %d %v %v", status, claims, err)
	}
	if _, err := claimsOf(mainToken, secondKeys); err == nil {
		t.Fatal("the surface tenant's token verifies against the exchange tenant's key set")
	}
	if status, out := exchange(unserved); status != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Fatalf("a tenant the exchange does not serve: HTTP %d %v", status, out)
	}

	info, published := h.srv.OIDCIssuerFor(httptest.NewRequest(http.MethodGet, "/api/v1/workloads/oidc-issuer", nil), second)
	if !published || info.TrustDomain != "second.m4l5.served.test" || info.Issuer != issuerBase+"/oidc/"+second || len(info.Algorithms) == 0 {
		t.Fatalf("the exchange tenant's issuer view = %+v (published %v)", info, published)
	}
	if _, published := h.srv.OIDCIssuerFor(httptest.NewRequest(http.MethodGet, "/api/v1/workloads/oidc-issuer", nil), unserved); published {
		t.Fatal("a tenant the exchange does not serve has a published issuer")
	}
	rotated, err := h.srv.RotateWorkloadJWTKey(t.Context(), second, 0, time.Hour)
	if err != nil || len(rotated) != 2 {
		t.Fatalf("rotate the exchange tenant's key = %+v %v", rotated, err)
	}
	if keys, served, err := h.srv.WorkloadJWTKeysFor(t.Context(), main); err != nil || !served || len(keys) != 1 {
		t.Fatalf("the surface tenant's ring after the other tenant rotated = %+v %v %v; want its one key", keys, served, err)
	}
	h.srv.exchangeFor(second).jwtKeys.invalidate()
	status, out = exchange(second)
	rotatedToken, _ := out["access_token"].(string)
	if _, err := claimsOf(rotatedToken, keySet("/oidc/"+second+"/jwks.json")); status != http.StatusOK || err != nil {
		t.Fatalf("after the rotation: HTTP %d %v", status, err)
	}
	if _, err := claimsOf(rotatedToken, secondKeys); err == nil {
		t.Fatal("the rotated tenant still signs with its first key")
	}
	t.Logf("M4L5_EXCHANGE_TENANTS_OK second=%s trust_domain=%s rotated_generations=%d", second, info.TrustDomain, len(rotated))
}
