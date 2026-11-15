// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// oauthJWTRefreshLab is an authorization server for one confidential client
// that authenticates by private_key_jwt (A239-L7), written from RFC 6749, RFC
// 7009 and RFC 7523. It verifies each client assertion through the crypto
// boundary against the client's registered key (issuer and subject the
// client, audience the token endpoint, one minute, a jti it has not seen) and
// refuses HTTP Basic; it serves the client-credentials grant and the
// refresh-token grant on the one refresh token it issued the client (a
// refresh may narrow its scope, never widen it); and its resource accepts an
// unrevoked, unexpired token that carries orders.read.
type oauthJWTRefreshLab struct {
	mu          sync.Mutex
	tokenURL    string
	jwks        crypto.JWKS
	grant       string
	grantScopes []string
	jtis        map[string]bool
	basic       int
	tokens      map[string]oauthJWTRefreshToken
	revocations []string
}

type oauthJWTRefreshToken struct {
	grant, scope string
	expires      time.Time
	revoked      bool
}

func newOAuthJWTRefreshLab(t *testing.T, keyPEM []byte, kid, grant string, grantScopes []string) (*oauthJWTRefreshLab, *httptest.Server) {
	t.Helper()
	der, err := crypto.PublicKeyDERFromPEMKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := crypto.PublicJWK(crypto.PublicKey{DER: der}, kid)
	if err != nil {
		t.Fatal(err)
	}
	lab := &oauthJWTRefreshLab{jwks: crypto.JWKS{Keys: []crypto.JWK{jwk}}, grant: grant, grantScopes: grantScopes,
		jtis: map[string]bool{}, tokens: map[string]oauthJWTRefreshToken{}}
	srv := httptest.NewServer(http.HandlerFunc(lab.serve))
	lab.tokenURL = srv.URL + "/token"
	t.Cleanup(srv.Close)
	return lab, srv
}

func (l *oauthJWTRefreshLab) reply(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (l *oauthJWTRefreshLab) serve(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.URL.Path == "/orders" {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		issued, known := l.tokens[token]
		if !ok || !known || issued.revoked || time.Now().After(issued.expires) || !slices.Contains(strings.Fields(issued.scope), "orders.read") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"orders":[]}`))
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !l.authenticated(r) {
		l.reply(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	switch r.URL.Path {
	case "/token":
		grant, scope := r.PostForm.Get("grant_type"), r.PostForm.Get("scope")
		switch grant {
		case "client_credentials":
		case "refresh_token":
			if r.PostForm.Get("refresh_token") != l.grant {
				l.reply(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
				return
			}
			for _, s := range strings.Fields(scope) {
				if !slices.Contains(l.grantScopes, s) {
					l.reply(w, http.StatusBadRequest, map[string]any{"error": "invalid_scope"})
					return
				}
			}
		default:
			l.reply(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
			return
		}
		raw, err := crypto.RandomBytes(16)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		token := hex.EncodeToString(raw)
		l.tokens[token] = oauthJWTRefreshToken{grant: grant, scope: scope, expires: time.Now().Add(5 * time.Minute)}
		body := map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 300, "scope": scope}
		if grant == "refresh_token" {
			// The refresh token, as a server that does not rotate it returns
			// it again.
			body["refresh_token"] = l.grant
		}
		l.reply(w, http.StatusOK, body)
	case "/revoke":
		token := r.PostForm.Get("token")
		l.revocations = append(l.revocations, r.PostForm.Get("token_type_hint")+" "+token)
		if issued, ok := l.tokens[token]; ok {
			issued.revoked = true
			l.tokens[token] = issued
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (l *oauthJWTRefreshLab) authenticated(r *http.Request) bool {
	if _, _, basic := r.BasicAuth(); basic {
		l.basic++
		return false
	}
	if r.PostForm.Get("client_id") != "trstctl-leases" || r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return false
	}
	raw, err := crypto.VerifyJWT(r.PostForm.Get("client_assertion"), l.jwks)
	if err != nil {
		return false
	}
	var c struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Jti string `json:"jti"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	now := time.Now().Unix()
	if json.Unmarshal(raw, &c) != nil || c.Iss != "trstctl-leases" || c.Sub != "trstctl-leases" || c.Aud != l.tokenURL ||
		c.Jti == "" || l.jtis[c.Jti] || c.Exp-c.Iat != 60 || c.Iat > now+5 || c.Exp <= now {
		return false
	}
	l.jtis[c.Jti] = true
	return true
}

func (l *oauthJWTRefreshLab) token(access string) oauthJWTRefreshToken {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tokens[access]
}

func (l *oauthJWTRefreshLab) state() (jtis, basic int, revocations []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.jtis), l.basic, append([]string(nil), l.revocations...)
}

// A239-L7 served: an oauth-client-credentials provider whose client
// authenticates by private_key_jwt, with a refresh-token role. The catalog
// states both; a reader lease is an access token drawn with the provider's
// refresh token, narrowed to orders.read, a writer lease one from the client
// credentials grant; each request carries its own client assertion and no
// secret; no response carries the refresh token or the key. Revoking the
// reader lease revokes its access token only (RFC 7009), which the resource
// then refuses, and the provider's grant serves the next reader lease.
func TestServedDynamicOAuthPrivateKeyJWTAndRefreshRolesA239L7(t *testing.T) {
	keyPEM, _, err := crypto.GenerateEdgeCAKeyAndCSR("a239l7 served client")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	grant := "lab-grant." + hex.EncodeToString(raw)
	lab, srv := newOAuthJWTRefreshLab(t, keyPEM, "trstctl-leases-1", grant, []string{"orders.read", "orders.write"})
	// Its own tenant: its leases stay out of the shared served tenant's
	// other tests.
	const tenant = "a2390007-39a7-4a39-8a39-0000a2390007"
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: tenant, ID: "orders-jwt", Type: "oauth-client-credentials", Endpoint: srv.URL + "/token",
		RevocationEndpoint: srv.URL + "/revoke", ClientID: "trstctl-leases", ClientAuth: "private_key_jwt",
		PrivateKeyRef: writeServedCredentialFile(t, "oauth-client-key", string(keyPEM)), ClientKeyID: "trstctl-leases-1",
		RefreshTokenRef: writeServedCredentialFile(t, "oauth-refresh", grant+"\n"), RefreshTokenRoles: []string{"reader"},
		AllowedRoles: []string{"reader", "writer"}, RoleBindings: map[string]string{"reader": "orders.read", "writer": "orders.read orders.write"},
		MaxTTL: "5m", AllowInsecureLoopback: true,
	}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenantID(t, h, tenant, "A239-L7 OAuth tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, tenant, "secrets:read", "secrets:write")
	leaks := func(stage string, body []byte) {
		t.Helper()
		if strings.Contains(string(body), grant) || strings.Contains(string(body), "PRIVATE KEY") {
			t.Fatalf("%s: the response carries the refresh token or the client key: %s", stage, body)
		}
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/providers", tok, nil)
	var catalog struct {
		ConfiguredProviders []struct {
			ID                string   `json:"id"`
			Revocation        string   `json:"revocation"`
			ClientAuth        string   `json:"client_auth"`
			RefreshTokenRoles []string `json:"refresh_token_roles"`
		} `json:"configured_providers"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &catalog) != nil || len(catalog.ConfiguredProviders) != 1 {
		t.Fatalf("provider catalog: %d %s", status, body)
	}
	leaks("catalog", body)
	if p := catalog.ConfiguredProviders[0]; p.ID != "orders-jwt" || p.Revocation != "confirmed" || p.ClientAuth != "private_key_jwt" ||
		!slices.Equal(p.RefreshTokenRoles, []string{"reader"}) {
		t.Fatalf("the configured provider reads %+v", p)
	}

	issue := func(role, key string) (dynamicLeaseView, string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, key,
			map[string]any{"provider": "orders-jwt", "role": role, "ttl_seconds": 60})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("issue a %s lease: %d %s", role, status, body)
		}
		leaks(role+" lease", body)
		var lease dynamicLeaseView
		if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
			t.Fatalf("decode the %s lease: %v %s", role, err, body)
		}
		var credential map[string]any
		if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil {
			t.Fatal(err)
		}
		access, _ := credential["access_token"].(string)
		if _, ok := credential["refresh_token"]; ok || access == "" || credential["token_type"] != "Bearer" {
			t.Fatalf("the %s credential: %v", role, credential)
		}
		return lease, access
	}
	resource := func(token string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orders", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	reader, readerToken := issue("reader", "a239l7-lease-1")
	if got := lab.token(readerToken); got.grant != "refresh_token" || got.scope != "orders.read" {
		t.Fatalf("the reader lease was issued %+v, want the refresh grant narrowed to orders.read", got)
	}
	if code := resource(readerToken); code != http.StatusOK {
		t.Fatalf("the resource refused the reader lease's token: %d", code)
	}
	_, writerToken := issue("writer", "a239l7-lease-2")
	if got := lab.token(writerToken); got.grant != "client_credentials" || got.scope != "orders.read orders.write" {
		t.Fatalf("the writer lease was issued %+v, want the client credentials grant", got)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+reader.ID+"/renew", tok, map[string]any{"extend_seconds": 10})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "can't be extended") {
		t.Fatalf("a refresh-role lease was extended: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+reader.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+reader.ID, tok, nil)
		var revoked dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &revoked) == nil && revoked.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code := resource(readerToken); code != http.StatusUnauthorized {
		t.Fatalf("the resource still accepts the revoked reader token: %d", code)
	}
	_, nextToken := issue("reader", "a239l7-lease-3")
	if got := lab.token(nextToken); got.grant != "refresh_token" || resource(nextToken) != http.StatusOK {
		t.Fatalf("after a revocation the provider's grant did not serve the next reader lease: %+v", got)
	}
	jtis, basic, revocations := lab.state()
	if want := []string{"access_token " + readerToken}; !slices.Equal(revocations, want) {
		t.Fatalf("revocations %v, want %v: the provider's refresh token is never revoked", revocations, want)
	}
	// Three token requests and one revocation, each with its own assertion.
	if jtis != 4 || basic != 0 {
		t.Fatalf("%d assertions and %d Basic attempts, want 4 and none", jtis, basic)
	}
	t.Logf("A239L7_OK reader=%s assertions=%d revocations=%d", reader.ID, jtis, len(revocations))
}
