// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// n5CloudSTS stands in for a cloud's token exchange (AWS
// AssumeRoleWithWebIdentity, Google STS, Azure federated credentials): it
// trusts one registered issuer and audience, fetches the issuer's discovery
// document and then its jwks_uri over HTTPS, verifies the token's signature,
// issuer, audience, expiry and a subject condition, and only then answers with
// a credential.
type n5CloudSTS struct {
	issuer, audience, subject string
	client                    *http.Client
	now                       func() time.Time
}

func (c *n5CloudSTS) exchange(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("InvalidIdentityToken: not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("InvalidIdentityToken: payload")
	}
	var unverified struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &unverified) != nil || unverified.Iss != c.issuer {
		return "", fmt.Errorf("InvalidIdentityToken: issuer %q is not a registered provider", unverified.Iss)
	}
	get := func(u string, into any) error {
		resp, err := c.client.Get(u)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
		}
		return json.NewDecoder(resp.Body).Decode(into)
	}
	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := get(c.issuer+"/.well-known/openid-configuration", &discovery); err != nil || discovery.Issuer != c.issuer || discovery.JWKSURI == "" {
		return "", fmt.Errorf("InvalidIdentityToken: discovery %+v: %v", discovery, err)
	}
	var keys crypto.JWKS
	if err := get(discovery.JWKSURI, &keys); err != nil {
		return "", fmt.Errorf("InvalidIdentityToken: keys: %w", err)
	}
	raw, err := crypto.VerifyJWT(token, keys)
	if err != nil {
		return "", fmt.Errorf("InvalidIdentityToken: signature: %w", err)
	}
	var claims struct {
		Iss string   `json:"iss"`
		Sub string   `json:"sub"`
		Aud []string `json:"aud"`
		Exp int64    `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Iss != c.issuer {
		return "", errors.New("InvalidIdentityToken: issuer claim")
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != c.audience {
		return "", fmt.Errorf("InvalidIdentityToken: audience %v", claims.Aud)
	}
	if !c.now().Before(time.Unix(claims.Exp, 0)) {
		return "", errors.New("ExpiredTokenException")
	}
	if claims.Sub != c.subject {
		return "", fmt.Errorf("AccessDenied: subject %q does not meet the role's condition", claims.Sub)
	}
	return "ASIAN5STANDIN" + strings.ToUpper(uuid.NewString()[:8]), nil
}

type n5RoundTrip func(*http.Request) (*http.Response, error)

func (f n5RoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// N5: a tenant's workloads exchange their platform token for a token trstctl
// signs with the signer-held key and publishes an OpenID issuer for, so a cloud
// trusts trstctl directly. The issuer is per tenant: a cloud trust registered
// for one tenant's issuer never accepts a token naming another, and a tenant the
// exchange does not serve has no issuer.
func TestServedOIDCIssuerIsTrustedByACloudTokenExchangeN5(t *testing.T) {
	const issuerBase = "https://issuer.trstctl.example.test"
	// Its own tenants, so its single-use records never meet another test's.
	tenantA := uuid.NewSHA1(uuid.NameSpaceOID, []byte("n5-exchange-tenant")).String()
	tenantB := uuid.NewSHA1(uuid.NameSpaceOID, []byte("n5-other-tenant")).String()
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
	const n5Issuer = m4K8sIssuer + "/n5"
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{
		{Name: "kubernetes", TenantID: tenantA, Issuer: n5Issuer, Audience: "trstctl",
			JWKSJSON: string(jwks), AllowedNamespaces: []string{"payments"}, Scopes: []string{"certs:read"}},
		{Name: "kubernetes", TenantID: tenantB, Issuer: n5Issuer + "/b", Audience: "trstctl",
			JWKSJSON: string(jwks), AllowedNamespaces: []string{"payments"}, Scopes: []string{"certs:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	protocols := config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: tenantA, TrustDomain: "served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		OIDCIssuerURL: issuerBase,
	}}
	if errs := protocols.ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("the protocols as configured: %v", errs)
	}
	h := newOperatingServedHarness(t, protocols, func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenantID(t, h, tenantA, "N5 exchange tenant")
	registerServedTenantID(t, h, tenantB, "N5 other tenant")
	projected := func(issuer, namespace, sa string) string {
		t.Helper()
		now := time.Now()
		tok, err := crypto.SignJWT(signer, "cluster-sa-key", map[string]any{
			"iss": issuer, "aud": []string{"trstctl"}, "sub": "system:serviceaccount:" + namespace + ":" + sa,
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
			"kubernetes.io": map[string]any{"namespace": namespace,
				"serviceaccount": map[string]any{"name": sa, "uid": uuid.NewString()},
				"pod":            map[string]any{"name": sa + "-7d9f", "uid": uuid.NewString()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	exchangeStatus := func(tenant, subject, audience string) (int, string, string) {
		t.Helper()
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {subject},
			"subject_token_type": {tokenTypeJWT}, "audience": {audience}}
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		var out struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.Unmarshal(body, &out)
		return resp.StatusCode, out.AccessToken, string(body)
	}
	exchange := func(tenant, subject, audience string) string {
		t.Helper()
		status, token, body := exchangeStatus(tenant, subject, audience)
		if status != http.StatusOK || token == "" {
			t.Fatalf("exchange for %s: HTTP %d %s", tenant, status, body)
		}
		return token
	}

	// The operator reads the issuer to register with the cloud.
	reader := seedScopedToken(t, h.store, tenantA, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/workloads/oidc-issuer", reader, nil)
	var info struct {
		Issuer       string   `json:"issuer"`
		DiscoveryURL string   `json:"discovery_url"`
		JWKSURI      string   `json:"jwks_uri"`
		Algorithms   []string `json:"algorithms"`
		Lifetime     int      `json:"token_lifetime_seconds"`
	}
	wantIssuer := issuerBase + "/oidc/" + tenantA
	if status != http.StatusOK || json.Unmarshal(body, &info) != nil || info.Issuer != wantIssuer ||
		info.DiscoveryURL != wantIssuer+"/.well-known/openid-configuration" || info.JWKSURI != wantIssuer+"/jwks.json" ||
		len(info.Algorithms) == 0 || info.Lifetime != 300 {
		t.Fatalf("oidc issuer: HTTP %d %s", status, body)
	}

	// The cloud reaches the issuer host; here it resolves to the served control plane.
	served, _ := url.Parse(h.ts.URL)
	cloudClient := &http.Client{Timeout: 10 * time.Second, Transport: n5RoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "issuer.trstctl.example.test" {
			return nil, fmt.Errorf("the cloud only reaches the registered issuer, not %s", r.URL)
		}
		forward := r.Clone(r.Context())
		forward.URL.Scheme, forward.URL.Host, forward.Host = served.Scheme, served.Host, served.Host
		return h.ts.Client().Transport.RoundTrip(forward)
	})}
	cloud := &n5CloudSTS{issuer: wantIssuer, audience: "sts.amazonaws.com", subject: "spiffe://served.test/ns/payments/sa/api",
		client: cloudClient, now: time.Now}
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("Action") != "AssumeRoleWithWebIdentity" {
			http.Error(w, "<Error><Code>InvalidAction</Code></Error>", http.StatusBadRequest)
			return
		}
		key, err := cloud.exchange(r.PostForm.Get("WebIdentityToken"))
		if err != nil {
			http.Error(w, "<Error><Message>"+err.Error()+"</Message></Error>", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>", key)
	}))
	t.Cleanup(stsServer.Close)
	assume := func(token string) (int, string) {
		t.Helper()
		resp, err := http.PostForm(stsServer.URL, url.Values{"Action": {"AssumeRoleWithWebIdentity"},
			"RoleArn": {"arn:aws:iam::123456789012:role/payments"}, "WebIdentityToken": {token}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	token := exchange(tenantA, projected(n5Issuer, "payments", "api"), "sts.amazonaws.com")
	if code, body := assume(token); code != http.StatusOK || !strings.Contains(body, "<AccessKeyId>ASIAN5STANDIN") {
		t.Fatalf("the cloud refused the tenant's token: HTTP %d %s", code, body)
	}
	// A trust registered for another tenant's issuer refuses this tenant's
	// token; that tenant has no issuer and cannot exchange.
	otherTrust := &n5CloudSTS{issuer: issuerBase + "/oidc/" + tenantB, audience: "sts.amazonaws.com",
		subject: "spiffe://served.test/ns/payments/sa/api", client: cloudClient, now: time.Now}
	if _, err := otherTrust.exchange(token); err == nil || !strings.Contains(err.Error(), "is not a registered provider") {
		t.Fatalf("a trust for another tenant's issuer accepted the token: %v", err)
	}
	if status, _, body := exchangeStatus(tenantB, projected(n5Issuer+"/b", "payments", "api"), "sts.amazonaws.com"); status != http.StatusBadRequest {
		t.Fatalf("a tenant the exchange does not serve got a token: HTTP %d %s", status, body)
	}
	readerB := seedScopedToken(t, h.store, tenantB, "certs:read")
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/workloads/oidc-issuer", readerB, nil); status != http.StatusNotFound {
		t.Fatalf("a tenant the exchange does not serve has an issuer: HTTP %d %s", status, body)
	}
	// A token for another audience, a tampered one and an expired one are refused.
	wrongAudience := exchange(tenantA, projected(n5Issuer, "payments", "api"), "https://payments.internal")
	if code, body := assume(wrongAudience); code == http.StatusOK || !strings.Contains(body, "audience") {
		t.Fatalf("the cloud accepted another audience: HTTP %d %s", code, body)
	}
	parts := strings.Split(token, ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(claims), "/sa/api", "/sa/adm", 1))) + "." + parts[2]
	if code, body := assume(tampered); code == http.StatusOK || !strings.Contains(body, "signature") {
		t.Fatalf("the cloud accepted a tampered token: HTTP %d %s", code, body)
	}
	cloud.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	if code, body := assume(token); code == http.StatusOK || !strings.Contains(body, "ExpiredToken") {
		t.Fatalf("the cloud accepted an expired token: HTTP %d %s", code, body)
	}

	// The documents are public; a malformed tenant ID, and a tenant the
	// exchange does not serve, are not issuers.
	for _, path := range []string{"/oidc/not-a-tenant/.well-known/openid-configuration", "/oidc/not-a-tenant/jwks.json",
		"/oidc/" + tenantB + "/.well-known/openid-configuration", "/oidc/" + tenantB + "/jwks.json"} {
		resp, err := h.ts.Client().Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
	t.Logf("N5_OIDC_ISSUER_OK issuer=%s algorithms=%v", info.Issuer, info.Algorithms)
}
