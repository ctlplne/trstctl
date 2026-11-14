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
	"trstctl.com/trstctl/internal/signing"
)

// N5-L2: with protocols.spiffe.exchange_all_tenants every live tenant has an
// issuer and an exchange, created on first use with its own JWT key, in its
// own trust domain under the suffix. A cloud fetching a tenant's discovery
// document finds its issuer and key set before any exchange; another tenant's
// exchanged JWT-SVID names its own trust domain and issuer and verifies only
// against its own key set; a tenant that is not registered has no issuer, no
// exchange and no key.
func TestServedEveryLiveTenantHasAnIssuerN5L2(t *testing.T) {
	const issuerBase = "https://issuer-n5l2.trstctl.example.test"
	const suffix = "tenants.n5l2.served.test"
	surface := uuid.NewSHA1(uuid.NameSpaceOID, []byte("n5l2-surface-tenant")).String()
	first := uuid.NewSHA1(uuid.NameSpaceOID, []byte("n5l2-first-tenant")).String()
	second := uuid.NewSHA1(uuid.NameSpaceOID, []byte("n5l2-second-tenant")).String()
	unregistered := uuid.NewSHA1(uuid.NameSpaceOID, []byte("n5l2-unregistered-tenant")).String()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "n5l2-sa-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	issuerOf := map[string]string{second: m4K8sIssuer + "/n5l2-b", unregistered: m4K8sIssuer + "/n5l2-u"}
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
		Enabled: true, TenantID: surface, TrustDomain: "n5l2.served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		OIDCIssuerURL: issuerBase, ExchangeAllTenants: true, TenantTrustDomainSuffix: suffix,
	}}
	if errs := protocols.ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("the protocols as configured: %v", errs)
	}
	h := newOperatingServedHarness(t, protocols, func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenantID(t, h, surface, "N5-L2 surface tenant")
	registerServedTenantID(t, h, first, "N5-L2 first tenant")
	registerServedTenantID(t, h, second, "N5-L2 second tenant")
	get := func(path string) (int, []byte) {
		t.Helper()
		resp, err := h.ts.Client().Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var buf strings.Builder
		var raw json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&raw)
		buf.Write(raw)
		return resp.StatusCode, []byte(buf.String())
	}
	keySet := func(tenant string) crypto.JWKS {
		t.Helper()
		status, body := get("/oidc/" + tenant + "/jwks.json")
		var set crypto.JWKS
		if status != http.StatusOK || json.Unmarshal(body, &set) != nil || len(set.Keys) == 0 {
			t.Fatalf("the key set of %s: HTTP %d", tenant, status)
		}
		return set
	}

	// A cloud reads the first tenant's discovery document before any exchange.
	status, body := get("/oidc/" + first + "/.well-known/openid-configuration")
	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &discovery) != nil || discovery.Issuer != issuerBase+"/oidc/"+first {
		t.Fatalf("the first tenant's discovery document: HTTP %d %s", status, body)
	}
	firstKeys := keySet(first)

	// The second tenant exchanges a pod token.
	now := time.Now()
	subject, err := crypto.SignJWT(signer, "n5l2-sa-key", map[string]any{
		"iss": issuerOf[second], "aud": []string{"trstctl"}, "sub": "system:serviceaccount:payments:api",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
		"kubernetes.io": map[string]any{"namespace": "payments", "serviceaccount": map[string]any{"name": "api", "uid": uuid.NewString()},
			"pod": map[string]any{"name": "api-7d9f", "uid": uuid.NewString()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(tenant, subject string) (int, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {subject}, "subject_token_type": {tokenTypeJWT},
			"audience": {"https://payments.internal"}}
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
	status, out := exchange(second, subject)
	token, _ := out["access_token"].(string)
	if status != http.StatusOK {
		t.Fatalf("the second tenant's exchange: HTTP %d %v", status, redactedExchange(out))
	}
	raw, err := crypto.VerifyJWTBytes([]byte(token), keySet(second))
	var claims struct {
		Sub string `json:"sub"`
		Iss string `json:"iss"`
	}
	trustDomain := strings.ReplaceAll(second, "-", "") + "." + suffix
	if err != nil || json.Unmarshal(raw, &claims) != nil || claims.Sub != "spiffe://"+trustDomain+"/ns/payments/sa/api" || claims.Iss != issuerBase+"/oidc/"+second {
		t.Fatalf("the second tenant's JWT-SVID = %+v %v", claims, err)
	}
	if _, err := crypto.VerifyJWTBytes([]byte(token), firstKeys); err == nil {
		t.Fatal("the second tenant's token verifies against the first tenant's key set")
	}
	info, published := h.srv.OIDCIssuerFor(httptest.NewRequest(http.MethodGet, "/api/v1/workloads/oidc-issuer", nil), second)
	if !published || info.TrustDomain != trustDomain {
		t.Fatalf("the second tenant's issuer view = %+v (published %v)", info, published)
	}

	// A tenant that is not registered gets nothing, and no key is made for it.
	if status, _ := get("/oidc/" + unregistered + "/.well-known/openid-configuration"); status != http.StatusNotFound {
		t.Fatalf("an unregistered tenant's discovery document: HTTP %d", status)
	}
	if status, out := exchange(unregistered, subject); status != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Fatalf("an unregistered tenant's exchange: HTTP %d %v", status, out)
	}
	if _, err := h.srv.signerForPrivilegedHandle(t.Context(), h.srv.signer.Client(), workloadJWTTenantHandle(unregistered), signing.PurposeGeneric); err == nil {
		t.Fatal("a JWT key was made for an unregistered tenant")
	}
	t.Logf("N5L2_EVERY_TENANT_OK first=%s second_trust_domain=%s", discovery.Issuer, trustDomain)
}
