// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
)

// A222: the Provider console signs in through the OIDC code flow. The login
// redirect carries state, nonce and a PKCE S256 challenge; the callback
// refuses a wrong state, redeems the code with the verifier and the client
// secret, holds the ID token to the bearer checks plus the nonce, and answers
// with an HttpOnly session cookie and no token anywhere the browser can read.
// The session authenticates the console, a mutation without the CSRF header
// is refused, a directory leaver is refused at once, and logout revokes it.
func TestProviderOIDCLoginMintsAnHttpOnlySession(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	access := newAUD58AccessStore()
	access.identities["operator-1"] = OperatorIdentity{ID: "operator-1", ExternalID: "kc-sub-1", UserName: "dana@provider.example",
		Email: "dana@provider.example", Role: OperatorAdmin, Active: true, Source: "scim:keycloak"}
	var nonce string
	var exchanged url.Values
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if r.ParseForm() != nil || !ok || user != "trstctl-provider" || pass != "client-secret" {
			http.Error(w, "unauthorized client", http.StatusUnauthorized)
			return
		}
		exchanged = r.PostForm
		if r.PostForm.Get("code") != "code-1" ||
			auth.PKCEChallengeS256(r.PostForm.Get("code_verifier")) == "" {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		claims := f.baseClaims()
		claims["sub"], claims["aud"], claims["nonce"] = "kc-sub-1", "trstctl-provider", nonce
		idToken, err := crypto.SignJWT(f.signer, "idp-k1", claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken, "access_token": "opaque-access", "token_type": "Bearer"})
	}))
	t.Cleanup(idp.Close)
	login := NewOIDCLogin(OIDCLoginConfig{
		Verifier: OIDCAuthenticatorConfig{
			Issuer: "https://idp.provider.example", JWKS: f.auth.cfg.JWKS, RoleClaim: "groups",
			AdminValues: []string{"trstctl-admins"}, MFAClaim: "amr", MFAValues: []string{"mfa"},
			Now: func() time.Time { return f.now }, Directory: access, RequireDirectory: true,
		},
		AuthorizationEndpoint: "https://idp.provider.example/auth", TokenEndpoint: idp.URL + "/token",
		ClientID: "trstctl-provider", ClientSecret: []byte("client-secret"), RedirectURL: "https://provider.example/provider/v1/auth/oidc/callback",
		HTTPClient: idp.Client(), SessionSecret: []byte("0123456789abcdef0123456789abcdef"), Secure: true,
	})
	if login == nil {
		t.Fatal("a complete OIDC login configuration did not build")
	}
	h := NewHandler(Config{License: providerLicense(t, 10), Authenticator: AnyAuthenticator{login}, Access: access, OIDCLogin: login,
		Mutations: &aud58MutationSink{store: access}})
	serve := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	start := serve(httptest.NewRequest(http.MethodGet, "/provider/v1/auth/oidc/login", nil))
	target, err := url.Parse(start.Header().Get("Location"))
	if start.Code != http.StatusFound || err != nil || target.Host != "idp.provider.example" {
		t.Fatalf("login = %d %q", start.Code, start.Header().Get("Location"))
	}
	q := target.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != "trstctl-provider" || q.Get("state") == "" || q.Get("nonce") == "" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorization request = %v; want code flow with state, nonce and PKCE S256", q)
	}
	nonce = q.Get("nonce")
	callback := func(state string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/provider/v1/auth/oidc/callback?code=code-1&state="+url.QueryEscape(state), nil)
		for _, c := range start.Result().Cookies() {
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("login state cookie %s is not HttpOnly and Lax", c.Name)
			}
			req.AddCookie(c)
		}
		return serve(req)
	}
	if wrong := callback("forged-state"); wrong.Code != http.StatusUnauthorized || len(exchanged) != 0 {
		t.Fatalf("callback with a wrong state = %d (exchanged %v); want 401 before any code exchange", wrong.Code, exchanged)
	}
	done := callback(q.Get("state"))
	if done.Code != http.StatusFound || done.Header().Get("Location") != "/provider" {
		t.Fatalf("callback = %d %s", done.Code, done.Body.String())
	}
	if exchanged.Get("redirect_uri") != "https://provider.example/provider/v1/auth/oidc/callback" ||
		auth.PKCEChallengeS256(exchanged.Get("code_verifier")) != q.Get("code_challenge") {
		t.Fatalf("token request %v does not carry the verifier for the challenge", exchanged)
	}
	var session, csrf *http.Cookie
	for _, c := range done.Result().Cookies() {
		if strings.Contains(c.Value, "opaque-access") || (c.Name != providerOIDCSessionCookie && strings.Count(c.Value, ".") == 2) {
			t.Fatalf("cookie %s carries a token", c.Name)
		}
		switch c.Name {
		case providerOIDCSessionCookie:
			session = c
		case providerCSRFCookie:
			csrf = c
		}
	}
	if session == nil || !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteStrictMode || session.Path != "/" || session.Domain != "" {
		t.Fatalf("session cookie = %+v; want HttpOnly, Secure, Strict, host-only", session)
	}
	if csrf == nil || csrf.HttpOnly || strings.Contains(done.Body.String(), "opaque-access") {
		t.Fatalf("csrf cookie = %+v, body %q", csrf, done.Body.String())
	}

	withSession := func(method, path string, csrfHeader bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.AddCookie(session)
		req.AddCookie(csrf)
		if csrfHeader {
			req.Header.Set(providerCSRFHeader, csrf.Value)
		}
		req.Header.Set("Idempotency-Key", "a222-"+method)
		return serve(req)
	}
	if me := withSession(http.MethodGet, "/provider/v1/auth/session", false); me.Code != http.StatusOK || !strings.Contains(me.Body.String(), "operator-1") {
		t.Fatalf("session read = %d %s; want the directory operator", me.Code, me.Body.String())
	}
	if forged := withSession(http.MethodPost, "/provider/v1/tenants", false); forged.Code != http.StatusForbidden {
		t.Fatalf("a session mutation without the CSRF header = %d; want 403", forged.Code)
	}
	if out := withSession(http.MethodPost, "/provider/v1/auth/logout", true); out.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %s", out.Code, out.Body.String())
	}
	if after := withSession(http.MethodGet, "/provider/v1/auth/session", false); after.Code != http.StatusUnauthorized {
		t.Fatalf("session after logout = %d; want 401", after.Code)
	}

	// A second sign-in, then the directory leaver: refused on the next request.
	start = serve(httptest.NewRequest(http.MethodGet, "/provider/v1/auth/oidc/login", nil))
	target, _ = url.Parse(start.Header().Get("Location"))
	nonce = target.Query().Get("nonce")
	done = callback(target.Query().Get("state"))
	for _, c := range done.Result().Cookies() {
		if c.Name == providerOIDCSessionCookie {
			session = c
		}
	}
	identity := access.identities["operator-1"]
	identity.Active = false
	access.identities["operator-1"] = identity
	if leaver := withSession(http.MethodGet, "/provider/v1/auth/session", false); leaver.Code != http.StatusUnauthorized {
		t.Fatalf("a deprovisioned operator's session = %d; want 401", leaver.Code)
	}
}
