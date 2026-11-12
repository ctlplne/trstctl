// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
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

const od6IssuerBase = "https://issuer.trstctl.example.test"

// od6Issuer is one served control plane publishing an OpenID issuer whose
// JWT keys the signer created with one algorithm, an exchanged workload token
// from it, and a cloud token exchange that accepts only RS256, as some clouds'
// workload federation does.
type od6Issuer struct {
	h        *servedHarness
	tenant   string
	token    string
	federate func(token string) (int, string)
}

func newOD6Issuer(t *testing.T, tenantSeed, algorithm string) od6Issuer {
	t.Helper()
	tenant := uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantSeed)).String()
	clusterKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clusterKey.Destroy)
	jwk, err := crypto.PublicJWK(clusterKey.Public(), "cluster-sa-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	clusterIssuer := m4K8sIssuer + "/" + tenantSeed
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{Name: "kubernetes", TenantID: tenant, Issuer: clusterIssuer,
		Audience: "trstctl", JWKSJSON: string(jwks), AllowedNamespaces: []string{"payments"}, Scopes: []string{"certs:read"}}})
	if err != nil {
		t.Fatal(err)
	}
	protocols := config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: tenant, TrustDomain: "served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		OIDCIssuerURL: od6IssuerBase, JWTKeyAlgorithm: algorithm,
	}}
	if errs := protocols.ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("the protocols as configured: %v", errs)
	}
	h := newOperatingServedHarness(t, protocols, func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenantID(t, h, tenant, "OD-6 exchange tenant")
	now := time.Now()
	projected, err := crypto.SignJWT(clusterKey, "cluster-sa-key", map[string]any{
		"iss": clusterIssuer, "aud": []string{"trstctl"}, "sub": "system:serviceaccount:payments:api",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
		"kubernetes.io": map[string]any{"namespace": "payments",
			"serviceaccount": map[string]any{"name": "api", "uid": uuid.NewString()},
			"pod":            map[string]any{"name": "api-7d9f", "uid": uuid.NewString()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {projected},
		"subject_token_type": {tokenTypeJWT}, "audience": {"api://AzureADTokenExchange"}}
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Tenant-ID", tenant)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &out) != nil || out.AccessToken == "" {
		t.Fatalf("exchange: HTTP %d %s", resp.StatusCode, body)
	}
	served, _ := url.Parse(h.ts.URL)
	cloudClient := &http.Client{Timeout: 10 * time.Second, Transport: n5RoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "issuer.trstctl.example.test" {
			return nil, fmt.Errorf("the cloud only reaches the registered issuer, not %s", r.URL)
		}
		forward := r.Clone(r.Context())
		forward.URL.Scheme, forward.URL.Host, forward.Host = served.Scheme, served.Host, served.Host
		return h.ts.Client().Transport.RoundTrip(forward)
	})}
	cloud := &n5CloudSTS{issuer: od6IssuerBase + "/oidc/" + tenant, audience: "api://AzureADTokenExchange",
		subject: "spiffe://served.test/ns/payments/sa/api", client: cloudClient, now: time.Now, algorithms: []string{"RS256"}}
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		key, err := cloud.exchange(r.PostForm.Get("client_assertion"))
		if err != nil {
			refusal, _ := json.Marshal(map[string]string{"error": "invalid_client", "error_description": err.Error()})
			http.Error(w, string(refusal), http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer"}`, key)
	}))
	t.Cleanup(sts.Close)
	federate := func(token string) (int, string) {
		t.Helper()
		resp, err := http.PostForm(sts.URL, url.Values{"grant_type": {"client_credentials"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {token}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	return od6Issuer{h: h, tenant: tenant, token: out.AccessToken, federate: federate}
}

func (o od6Issuer) public(t *testing.T, path string, into any) {
	t.Helper()
	resp, err := o.h.ts.Client().Get(o.h.ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(into) != nil {
		t.Fatalf("GET %s: HTTP %d", path, resp.StatusCode)
	}
}

func od6TokenAlgorithm(t *testing.T, token string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	var header struct {
		Alg string `json:"alg"`
	}
	if err != nil || json.Unmarshal(raw, &header) != nil {
		t.Fatalf("token header: %v", err)
	}
	return header.Alg
}

// OD-6 (N5-L1): with protocols.spiffe.jwt_key_algorithm RS256 the signer
// creates the workload JWT key as RSA, so a relying party that accepts only
// RS256 trusts the exchanged tokens: the issuer advertises RS256, publishes
// an RSA key and signs RS256, and a cloud token exchange that refuses any
// other algorithm accepts the token. A rotation's next key is RSA too. An
// unsupported algorithm is refused in configuration.
func TestServedOIDCIssuerSignsRS256ForRS256OnlyCloudsOD6(t *testing.T) {
	if errs := (config.Protocols{SPIFFE: config.SPIFFEProtocol{JWTKeyAlgorithm: "PS256"}}).ValidateTenantBindings(""); len(errs) == 0 ||
		!strings.Contains(fmt.Sprint(errs), "must be ES256 or RS256") {
		t.Fatalf("an unsupported algorithm = %v", errs)
	}
	o := newOD6Issuer(t, "od6-rs256-tenant", "RS256")
	if alg := od6TokenAlgorithm(t, o.token); alg != "RS256" {
		t.Fatalf("the exchanged token is %s, want RS256", alg)
	}
	var discovery struct {
		Algorithms []string `json:"id_token_signing_alg_values_supported"`
	}
	o.public(t, "/oidc/"+o.tenant+"/.well-known/openid-configuration", &discovery)
	if strings.Join(discovery.Algorithms, ",") != "RS256" {
		t.Fatalf("the issuer advertises %v, want RS256", discovery.Algorithms)
	}
	var keys crypto.JWKS
	o.public(t, "/oidc/"+o.tenant+"/jwks.json", &keys)
	if len(keys.Keys) != 1 || keys.Keys[0].Kty != "RSA" || keys.Keys[0].Alg != "RS256" {
		t.Fatalf("the published keys = %+v, want one RSA RS256 key", keys.Keys)
	}
	if code, body := o.federate(o.token); code != http.StatusOK || !strings.Contains(body, "ASIAN5STANDIN") {
		t.Fatalf("the RS256-only cloud refused the RS256 token: HTTP %d %s", code, body)
	}
	// A rotation's next key is RSA as well.
	rotator := seedScopedToken(t, o.h.store, o.tenant, "issuers:write")
	if status, raw := secretsReqKey(t, o.h, http.MethodPost, "/api/v1/workloads/jwt-keys/rotate", rotator, "od6-rotate",
		map[string]any{"publish_ahead_seconds": 3600}); status != http.StatusOK {
		t.Fatalf("rotate: HTTP %d %s", status, raw)
	}
	o.h.srv.spiffeForExchange().jwtKeys.invalidate()
	keys = crypto.JWKS{}
	o.public(t, "/oidc/"+o.tenant+"/jwks.json", &keys)
	if len(keys.Keys) != 2 || keys.Keys[0].Kty != "RSA" || keys.Keys[1].Kty != "RSA" {
		t.Fatalf("the published keys after a rotation = %+v, want two RSA keys", keys.Keys)
	}
}

// OD-6: by default the workload JWT key stays ES256, which a relying party
// that accepts only RS256 refuses: the reason the option exists.
func TestServedDefaultOIDCIssuerKeyStaysES256OD6(t *testing.T) {
	o := newOD6Issuer(t, "od6-es256-tenant", "")
	if alg := od6TokenAlgorithm(t, o.token); alg != "ES256" {
		t.Fatalf("the default exchanged token is %s, want ES256", alg)
	}
	if code, body := o.federate(o.token); code == http.StatusOK || !strings.Contains(body, `signing algorithm \"ES256\" is not supported`) {
		t.Fatalf("the RS256-only cloud accepted an ES256 token: HTTP %d %s", code, body)
	}
}
