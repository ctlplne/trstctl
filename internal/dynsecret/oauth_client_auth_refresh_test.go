// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// oauthAS is a local authorization server written from RFC 6749, RFC 7009
// and RFC 7523 (A239-L7): it authenticates the client by HTTP Basic or, given
// a JWKS, by a client assertion it verifies through the crypto boundary
// (issuer and subject the client, audience the token endpoint, one minute,
// a jti it has not seen); it serves the client-credentials and refresh-token
// grants (a refresh may narrow the refresh token's scope, never widen it),
// and records each revocation with its hint.
type oauthAS struct {
	mu          sync.Mutex
	tokenURL    string
	jwks        crypto.JWKS
	now         time.Time
	jtis        map[string]bool
	claims      []oauthAssertionClaims
	basic       int
	refresh     map[string][]string // a refresh token -> the scopes it was granted
	dead        map[string]bool     // refresh tokens no longer accepted
	issued      map[string]oauthIssued
	revoked     map[string]bool
	revocations []string // "<hint> <token>", in order
	addRefresh  bool     // a refresh token in every client-credentials response
	overgrant   string   // a scope the server adds to what it grants
	n           int
}

type oauthAssertionClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

type oauthIssued struct{ grant, scope, from string }

func newOAuthAS(t *testing.T, now time.Time, jwks crypto.JWKS) (*oauthAS, *httptest.Server) {
	t.Helper()
	as := &oauthAS{jwks: jwks, now: now, jtis: map[string]bool{}, refresh: map[string][]string{}, dead: map[string]bool{},
		issued: map[string]oauthIssued{}, revoked: map[string]bool{}}
	srv := httptest.NewTLSServer(as)
	as.tokenURL = srv.URL + "/token"
	t.Cleanup(srv.Close)
	return as, srv
}

func oauthReply(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (as *oauthAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if !as.authenticated(r) {
		oauthReply(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	switch r.URL.Path {
	case "/token":
		grant, scope, from := r.PostForm.Get("grant_type"), r.PostForm.Get("scope"), ""
		switch grant {
		case "client_credentials":
		case "refresh_token":
			from = r.PostForm.Get("refresh_token")
			granted, ok := as.refresh[from]
			if !ok || as.dead[from] {
				oauthReply(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
				return
			}
			for _, s := range strings.Fields(scope) {
				if !slices.Contains(granted, s) {
					oauthReply(w, http.StatusBadRequest, map[string]any{"error": "invalid_scope"})
					return
				}
			}
		default:
			oauthReply(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
			return
		}
		as.n++
		token := fmt.Sprintf("as-access-%d", as.n)
		as.issued[token] = oauthIssued{grant: grant, scope: scope, from: from}
		body := map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 300, "scope": strings.TrimSpace(scope + " " + as.overgrant)}
		if grant == "refresh_token" || as.addRefresh {
			// A refresh grant's rotated token, or one a server adds to a
			// client-credentials response.
			rotated := fmt.Sprintf("as-refresh-%d", as.n)
			as.refresh[rotated] = strings.Fields(scope)
			body["refresh_token"] = rotated
		}
		oauthReply(w, http.StatusOK, body)
	case "/revoke":
		hint, token := r.PostForm.Get("token_type_hint"), r.PostForm.Get("token")
		as.revocations = append(as.revocations, hint+" "+token)
		if _, ok := as.refresh[token]; ok {
			as.dead[token] = true
		} else {
			as.revoked[token] = true
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (as *oauthAS) authenticated(r *http.Request) bool {
	id, pass, basic := r.BasicAuth()
	if len(as.jwks.Keys) == 0 {
		as.basic++
		return basic && id == "lab-client" && pass == "lab+secret%2F" // #nosec G101 -- fabricated lab client secret, form-encoded (CWE-798)
	}
	if basic || r.PostForm.Get("client_id") != "lab-client" ||
		r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return false
	}
	raw, err := crypto.VerifyJWT(r.PostForm.Get("client_assertion"), as.jwks)
	if err != nil {
		return false
	}
	var c oauthAssertionClaims
	if json.Unmarshal(raw, &c) != nil || c.Iss != "lab-client" || c.Sub != "lab-client" || c.Aud != as.tokenURL ||
		c.Jti == "" || as.jtis[c.Jti] || c.Exp-c.Iat != 60 || c.Iat > as.now.Unix() || c.Exp <= as.now.Unix() {
		return false
	}
	as.jtis[c.Jti] = true
	as.claims = append(as.claims, c)
	return true
}

// labJWKS publishes the public half of a client key, as an authorization
// server registers it.
func labJWKS(t *testing.T, keyPEM []byte, kid string) crypto.JWKS {
	t.Helper()
	der, err := crypto.PublicKeyDERFromPEMKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := crypto.PublicJWK(crypto.PublicKey{DER: der}, kid)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.JWKS{Keys: []crypto.JWK{jwk}}
}

func newOAuthASBackend(t *testing.T, srv *httptest.Server, now time.Time, mutate func(*OAuthClientCredentialsConfig)) *OAuthClientCredentialsBackend {
	t.Helper()
	cfg := OAuthClientCredentialsConfig{
		TokenURL: srv.URL + "/token", RevocationURL: srv.URL + "/revoke", ClientID: "lab-client", ClientSecret: []byte("lab secret/"),
		RoleScopes:  map[string]string{"reader": "orders.read", "writer": "orders.read orders.write"},
		MaxLifetime: 10 * time.Minute, HTTPClient: srv.Client(), Now: func() time.Time { return now },
	}
	mutate(&cfg)
	b, err := NewOAuthClientCredentialsBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func oauthLeaseToken(t *testing.T, credential []byte) (string, map[string]json.RawMessage) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(credential, &fields); err != nil {
		t.Fatal(err)
	}
	var token string
	if err := json.Unmarshal(fields["access_token"], &token); err != nil {
		t.Fatal(err)
	}
	return token, fields
}

// TestOAuthPrivateKeyJWTClientAuthenticationA239L7: with client_auth
// private_key_jwt the client sends no secret; each token and revocation
// request carries a fresh client assertion signed with the client's key
// through the crypto boundary, which the server verifies against the key it
// registered (ES256 and RS256): issuer and subject the client, audience the
// token endpoint, valid one minute, a jti never reused. Another key, or a
// kid the server does not know, is refused as invalid_client.
func TestOAuthPrivateKeyJWTClientAuthenticationA239L7(t *testing.T) {
	now := time.Date(2026, 11, 15, 6, 0, 0, 0, time.UTC)
	ecKey, _, err := crypto.GenerateEdgeCAKeyAndCSR("a239l7 lab client")
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, _, err := crypto.GenerateUploadableRSAKeypair(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := crypto.GenerateEdgeCAKeyAndCSR("a239l7 another client")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for name, key := range map[string][]byte{"ES256": ecKey, "RS256": rsaKey} {
		t.Run(name, func(t *testing.T) {
			as, srv := newOAuthAS(t, now, labJWKS(t, key, "lab-key-1"))
			jwt := func(key []byte, kid string) func(*OAuthClientCredentialsConfig) {
				return func(c *OAuthClientCredentialsConfig) {
					c.ClientAuth, c.ClientSecret, c.ClientKeyPEM, c.ClientKeyID = OAuthPrivateKeyJWT, nil, key, kid
				}
			}
			b := newOAuthASBackend(t, srv, now, jwt(key, "lab-key-1"))
			if b.ClientAuth() != OAuthPrivateKeyJWT {
				t.Fatalf("ClientAuth() = %q", b.ClientAuth())
			}
			ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: "reader", TTL: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			token, _ := oauthLeaseToken(t, credential)
			if got := as.issued[token]; got.grant != "client_credentials" || got.scope != "orders.read" {
				t.Fatalf("issued %+v", got)
			}
			if err := b.RevokeCredential(ctx, ref, credential); err != nil || !as.revoked[token] {
				t.Fatalf("revoke: %v revoked=%v", err, as.revoked)
			}
			if len(as.claims) != 2 || len(as.jtis) != 2 || as.basic != 0 {
				t.Fatalf("assertions %+v, jtis %d, basic %d: want one fresh assertion per request and no secret", as.claims, len(as.jtis), as.basic)
			}
			for _, c := range as.claims {
				if c.Iss != "lab-client" || c.Sub != "lab-client" || c.Aud != srv.URL+"/token" || c.Iat != now.Unix() || c.Exp != now.Add(time.Minute).Unix() {
					t.Fatalf("assertion claims %+v", c)
				}
			}
			for label, cfg := range map[string]func(*OAuthClientCredentialsConfig){
				"another key":    jwt(otherKey, "lab-key-1"),
				"an unknown kid": jwt(key, "lab-key-2"),
			} {
				other := newOAuthASBackend(t, srv, now, cfg)
				if _, _, err := other.CreateCredential(ctx, GenerateRequest{Role: "reader", TTL: time.Minute}); err == nil ||
					!strings.Contains(err.Error(), "401: invalid_client") {
					t.Fatalf("%s: %v, want invalid_client", label, err)
				}
			}
		})
	}
}

// TestOAuthRefreshTokenRolesDrawLeasesFromTheProvidersGrantA239L7: a role in
// refresh_token_roles draws each lease's access token with the provider's
// refresh token (RFC 6749 section 6), its scope narrowed to the role's;
// other roles keep the client-credentials grant. The refresh token is in no
// lease credential, reference or revocation, and a rotated one the server
// returns is wiped, not kept: the next lease draws on the configured token
// again. Revoking a lease revokes its access token only (RFC 7009), so the
// provider's grant serves the next lease. A grant the server stops accepting
// fails the lease naming what to do; a scope beyond the role is refused and
// the token revoked.
func TestOAuthRefreshTokenRolesDrawLeasesFromTheProvidersGrantA239L7(t *testing.T) {
	now := time.Date(2026, 11, 15, 6, 0, 0, 0, time.UTC)
	ctx := context.Background()
	as, srv := newOAuthAS(t, now, crypto.JWKS{})
	const providerRefresh = "as-provider-grant"
	as.refresh[providerRefresh] = []string{"orders.read", "orders.write"}
	b := newOAuthASBackend(t, srv, now, func(c *OAuthClientCredentialsConfig) {
		c.RefreshToken, c.RefreshRoles = []byte(providerRefresh+"\n"), []string{"reader"}
	})
	if got := b.RefreshRoles(); !slices.Equal(got, []string{"reader"}) {
		t.Fatalf("RefreshRoles() = %v", got)
	}
	lease := func(role string) (string, []byte, string) {
		t.Helper()
		ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: role, TTL: time.Minute})
		if err != nil {
			t.Fatalf("%s lease: %v", role, err)
		}
		token, fields := oauthLeaseToken(t, credential)
		if _, ok := fields["refresh_token"]; ok || strings.Contains(string(credential), "as-refresh-") ||
			strings.Contains(string(credential), providerRefresh) || strings.Contains(ref, providerRefresh) {
			t.Fatalf("%s lease credential %s (ref %s) carries a refresh token", role, credential, ref)
		}
		return ref, credential, token
	}
	ref, credential, first := lease("reader")
	if got := as.issued[first]; got.grant != "refresh_token" || got.from != providerRefresh || got.scope != "orders.read" {
		t.Fatalf("reader lease issued %+v, want the refresh grant on the provider's token, narrowed to orders.read", got)
	}
	// The server rotated the refresh token in its answer; the next lease
	// still draws on the configured one.
	_, _, second := lease("reader")
	if got := as.issued[second]; got.from != providerRefresh {
		t.Fatalf("second reader lease drew on %q, want the configured refresh token", got.from)
	}
	_, _, writer := lease("writer")
	if got := as.issued[writer]; got.grant != "client_credentials" || got.scope != "orders.read orders.write" {
		t.Fatalf("writer lease issued %+v, want the client-credentials grant", got)
	}
	if err := b.RevokeCredential(ctx, ref, credential); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(as.revocations, []string{"access_token " + first}) || as.dead[providerRefresh] {
		t.Fatalf("revocations %v (provider grant dead=%v), want only the lease's access token", as.revocations, as.dead[providerRefresh])
	}
	_, _, third := lease("reader")
	if got := as.issued[third]; got.from != providerRefresh {
		t.Fatalf("after a revocation the reader lease drew on %q", got.from)
	}

	as.overgrant = "orders.admin"
	_, _, err := b.CreateCredential(ctx, GenerateRequest{Role: "reader", TTL: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "beyond the role: orders.admin") || !strings.Contains(err.Error(), "the token was revoked") {
		t.Fatalf("an overgranted refresh: %v", err)
	}
	if last := as.revocations[len(as.revocations)-1]; last != fmt.Sprintf("access_token as-access-%d", as.n) {
		t.Fatalf("the overgranted token was not the one revoked: %v", as.revocations)
	}
	as.overgrant = ""
	as.dead[providerRefresh] = true
	_, _, err = b.CreateCredential(ctx, GenerateRequest{Role: "reader", TTL: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "400: invalid_grant") || !strings.Contains(err.Error(), "configure a new refresh_token_ref") {
		t.Fatalf("a dead provider grant: %v", err)
	}
	for _, r := range as.revocations {
		if strings.Contains(r, providerRefresh) || strings.HasPrefix(r, "refresh_token") {
			t.Fatalf("a refresh token was sent for revocation: %v", as.revocations)
		}
	}
}

// TestOAuthUnrequestedRefreshTokenIsWipedA239L7: a server that adds a refresh
// token to a client-credentials answer gets nothing back for it: the lease
// carries the access token alone and the refresh token is neither kept nor
// revoked (revoking it ends, on some servers, the session the access token
// belongs to).
func TestOAuthUnrequestedRefreshTokenIsWipedA239L7(t *testing.T) {
	now := time.Date(2026, 11, 15, 6, 0, 0, 0, time.UTC)
	as, srv := newOAuthAS(t, now, crypto.JWKS{})
	as.addRefresh = true
	b := newOAuthASBackend(t, srv, now, func(*OAuthClientCredentialsConfig) {})
	ref, credential, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "writer", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	token, fields := oauthLeaseToken(t, credential)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"access_token", "expires_at", "scope", "token_type"}) || len(as.revocations) != 0 {
		t.Fatalf("credential fields %v, revocations %v", keys, as.revocations)
	}
	if err := b.RevokeCredential(context.Background(), ref, credential); err != nil || !slices.Equal(as.revocations, []string{"access_token " + token}) {
		t.Fatalf("revoke: %v %v", err, as.revocations)
	}
}

// TestOAuthClientAuthAndRefreshConfigA239L7: the backend refuses a
// configuration whose client authentication or refresh token cannot work.
func TestOAuthClientAuthAndRefreshConfigA239L7(t *testing.T) {
	base := func() OAuthClientCredentialsConfig {
		return OAuthClientCredentialsConfig{TokenURL: "https://as.example/token", ClientID: "c", ClientSecret: []byte("s"), // #nosec G101 -- fabricated fixture secret (CWE-798)
			RoleScopes: map[string]string{"reader": "orders.read"}, MaxLifetime: time.Minute, HTTPClient: http.DefaultClient}
	}
	for name, tc := range map[string]struct {
		mutate func(*OAuthClientCredentialsConfig)
		want   string
	}{
		"jwt without a key": {func(c *OAuthClientCredentialsConfig) { c.ClientAuth, c.ClientSecret = OAuthPrivateKeyJWT, nil }, "private_key_jwt needs the client's private key"},
		"jwt with no PEM": {func(c *OAuthClientCredentialsConfig) {
			c.ClientAuth, c.ClientKeyPEM = OAuthPrivateKeyJWT, []byte("not a key")
		}, "the client's private key"},
		"another method":           {func(c *OAuthClientCredentialsConfig) { c.ClientAuth = "client_secret_post" }, `"client_secret_post" is client_secret_basic or private_key_jwt`},
		"basic without the secret": {func(c *OAuthClientCredentialsConfig) { c.ClientSecret = nil }, "client_secret_basic needs the client secret"},
		"refresh roles, no token":  {func(c *OAuthClientCredentialsConfig) { c.RefreshRoles = []string{"reader"} }, "refresh-token roles need the provider's refresh token"},
		"blank token": {func(c *OAuthClientCredentialsConfig) {
			c.RefreshRoles, c.RefreshToken = []string{"reader"}, []byte(" \n")
		}, "refresh-token roles need the provider's refresh token"},
		"token, no role": {func(c *OAuthClientCredentialsConfig) { c.RefreshToken = []byte("rt") }, "a refresh token is configured but no role draws on it"},
		"refresh role, no scopes": {func(c *OAuthClientCredentialsConfig) {
			c.RefreshRoles, c.RefreshToken = []string{"writer"}, []byte("rt")
		}, `refresh-token role "writer" has no scopes`},
	} {
		cfg := base()
		tc.mutate(&cfg)
		if _, err := NewOAuthClientCredentialsBackend(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
