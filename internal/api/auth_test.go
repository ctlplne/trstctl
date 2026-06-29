package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/jose"
)

const (
	testTenant     = "11111111-1111-1111-1111-111111111111"
	testOIDCIssuer = "https://idp.example.test"
)

func authConfig() (api.AuthConfig, *auth.SessionIssuer) {
	sessions := auth.NewSessionIssuer([]byte("test-secret-0123456789abcdef0123"), time.Hour)
	cfg := api.AuthConfig{
		AuthEndpoint:  "https://idp.example.test/authorize",
		ClientID:      "trstctl-ui",
		RedirectURI:   "https://app.example.test/auth/callback",
		DefaultTenant: testTenant,
		Exchange: func(_ context.Context, code, _ string) (string, error) {
			if code == "good-code" {
				return "id-token-good", nil
			}
			return "", errors.New("bad code")
		},
		VerifyIDToken: func(idToken, nonce string) (auth.Claims, error) {
			if idToken == "id-token-good" {
				return auth.Claims{Subject: "user-1", Email: "u@example.test", Nonce: nonce}, nil
			}
			return auth.Claims{}, errors.New("bad id_token")
		},
		// Per-user → tenant mapping (TENANT-004): the callback now resolves the tenant
		// from claims rather than collapsing to DefaultTenant. Here every test user maps
		// to testTenant via the opt-in default, preserving the existing assertions while
		// exercising the new mapping seam.
		ResolveTenant: auth.TenantMapper{
			DefaultTenant: testTenant,
			DefaultRoles:  []string{"admin"},
			AllowDefault:  true,
		}.ResolveTenant,
		Sessions: sessions,
	}
	return cfg, sessions
}

func authAPI(t *testing.T) (http.Handler, *auth.SessionIssuer) {
	t.Helper()
	cfg, sessions := authConfig()
	return api.New(nil, nil, nil, api.WithAuth(cfg)), sessions
}

func TestAuthLoginRedirectsToIdP(t *testing.T) {
	h, _ := authAPI(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.example.test/authorize?") {
		t.Errorf("Location = %q, want the IdP authorize URL", loc)
	}
	if !strings.Contains(loc, "state=") || !strings.Contains(loc, "nonce=") || !strings.Contains(loc, "client_id=trstctl-ui") {
		t.Errorf("authorize URL missing params: %q", loc)
	}
	cookies := rec.Result().Cookies()
	var sawState, sawNonce bool
	for _, c := range cookies {
		if c.Name == "trstctl_oidc_state" {
			sawState = true
		}
		if c.Name == "trstctl_oidc_nonce" {
			sawNonce = true
		}
		if !c.HttpOnly {
			t.Errorf("cookie %s should be HttpOnly", c.Name)
		}
	}
	if !sawState || !sawNonce {
		t.Errorf("login must set state and nonce cookies")
	}
}

func TestAuthLoginUsesPKCES256(t *testing.T) {
	h, _ := authAPI(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		t.Fatal("authorization URL is missing code_challenge")
	}
	verifier := cookieValue(rec.Result().Cookies(), "trstctl_oidc_pkce")
	if verifier == "" {
		t.Fatal("login did not set the PKCE verifier cookie")
	}
	if got := auth.PKCEChallengeS256(verifier); got != challenge {
		t.Fatalf("code_challenge = %q, want challenge derived from verifier %q", challenge, got)
	}
}

func TestAuthCallbackEstablishesSession(t *testing.T) {
	var exchangedVerifier string
	cfg, sessions := authConfig()
	cfg.Exchange = func(_ context.Context, code, verifier string) (string, error) {
		exchangedVerifier = verifier
		if code == "good-code" {
			return "id-token-good", nil
		}
		return "", errors.New("bad code")
	}
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	state := cookieValue(login.Result().Cookies(), "trstctl_oidc_state")
	nonce := cookieValue(login.Result().Cookies(), "trstctl_oidc_nonce")
	verifier := cookieValue(login.Result().Cookies(), "trstctl_oidc_pkce")
	preLogin := cookieValue(login.Result().Cookies(), "trstctl_oidc_prelogin")
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_prelogin", Value: preLogin})
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_state", Value: state})
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_nonce", Value: nonce})
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_pkce", Value: verifier})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-trstctl_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("callback did not set a session cookie")
	}
	sess, err := sessions.Verify(session)
	if err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
	if sess.Subject != "user-1" || sess.TenantID != testTenant {
		t.Errorf("session = %+v", sess)
	}
	if exchangedVerifier != verifier {
		t.Fatalf("token exchange verifier = %q, want %q", exchangedVerifier, verifier)
	}
}

func TestAuthCallbackRejectsTamperedPKCEVerifier(t *testing.T) {
	var expectedChallenge string
	cfg, _ := authConfig()
	cfg.Exchange = func(_ context.Context, code, verifier string) (string, error) {
		if code == "good-code" && auth.PKCEChallengeS256(verifier) == expectedChallenge {
			return "id-token-good", nil
		}
		return "", errors.New("pkce verifier mismatch")
	}
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	loc, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	expectedChallenge = loc.Query().Get("code_challenge")
	preLogin := cookieValue(login.Result().Cookies(), "trstctl_oidc_prelogin")
	state := cookieValue(login.Result().Cookies(), "trstctl_oidc_state")
	nonce := cookieValue(login.Result().Cookies(), "trstctl_oidc_nonce")

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_prelogin", Value: preLogin})
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_state", Value: state})
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_nonce", Value: nonce})
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_pkce", Value: "tampered-verifier"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tampered PKCE verifier callback = %d, want 400", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-trstctl_session" && c.Value != "" {
			t.Fatal("tampered PKCE verifier established a session")
		}
	}
}

func TestAuthCallbackAcceptsMatchingPreLoginBinding(t *testing.T) {
	h, sessions := authAPI(t)
	login := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	loginReq.RemoteAddr = "203.0.113.10:1234"
	loginReq.Header.Set("User-Agent", "browser-a")
	h.ServeHTTP(login, loginReq)

	req := callbackFromLogin(t, login.Result().Cookies(), "good-code")
	req.RemoteAddr = "203.0.113.10:5678"
	req.Header.Set("User-Agent", "browser-a")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("matching callback = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	if session := cookieValue(rec.Result().Cookies(), "__Host-trstctl_session"); session == "" {
		t.Fatal("matching callback did not issue a session")
	} else if _, err := sessions.Verify(session); err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
}

func TestAuthCallbackRejectsPreLoginUserAgentMismatch(t *testing.T) {
	h, _ := authAPI(t)
	login := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	loginReq.RemoteAddr = "203.0.113.10:1234"
	loginReq.Header.Set("User-Agent", "browser-a")
	h.ServeHTTP(login, loginReq)

	req := callbackFromLogin(t, login.Result().Cookies(), "good-code")
	req.RemoteAddr = "203.0.113.10:5678"
	req.Header.Set("User-Agent", "browser-b")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("UA mismatch callback = %d, want 400", rec.Code)
	}
	if session := cookieValue(rec.Result().Cookies(), "__Host-trstctl_session"); session != "" {
		t.Fatal("UA mismatch established a session")
	}
}

func TestAuthCallbackRejectsPreLoginIPMismatch(t *testing.T) {
	h, _ := authAPI(t)
	login := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	loginReq.RemoteAddr = "203.0.113.10:1234"
	loginReq.Header.Set("User-Agent", "browser-a")
	h.ServeHTTP(login, loginReq)

	req := callbackFromLogin(t, login.Result().Cookies(), "good-code")
	req.RemoteAddr = "203.0.113.11:5678"
	req.Header.Set("User-Agent", "browser-a")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("IP mismatch callback = %d, want 400", rec.Code)
	}
	if session := cookieValue(rec.Result().Cookies(), "__Host-trstctl_session"); session != "" {
		t.Fatal("IP mismatch established a session")
	}
}

func TestAuthCallbackRejectsWrongAuthorizationResponseIssuer(t *testing.T) {
	cfg, _ := authConfig()
	cfg.Issuer = "https://idp.example.test"
	cfg.AuthorizationResponseIssParamSupported = true
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	req := callbackFromLoginWithIss(t, login.Result().Cookies(), "good-code", "https://attacker.example.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong iss callback = %d, want 400", rec.Code)
	}
	if session := cookieValue(rec.Result().Cookies(), "__Host-trstctl_session"); session != "" {
		t.Fatal("wrong iss callback established a session")
	}
}

func TestAuthCallbackRejectsMissingAuthorizationResponseIssuer(t *testing.T) {
	cfg, _ := authConfig()
	cfg.Issuer = "https://idp.example.test"
	cfg.AuthorizationResponseIssParamSupported = true
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	req := callbackFromLogin(t, login.Result().Cookies(), "good-code")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing iss callback = %d, want 400", rec.Code)
	}
	if session := cookieValue(rec.Result().Cookies(), "__Host-trstctl_session"); session != "" {
		t.Fatal("missing iss callback established a session")
	}
}

func TestAuthCallbackAcceptsMatchingAuthorizationResponseIssuer(t *testing.T) {
	cfg, sessions := authConfig()
	cfg.Issuer = "https://idp.example.test"
	cfg.AuthorizationResponseIssParamSupported = true
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	req := callbackFromLoginWithIss(t, login.Result().Cookies(), "good-code", "https://idp.example.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("matching iss callback = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	if session := cookieValue(rec.Result().Cookies(), "__Host-trstctl_session"); session == "" {
		t.Fatal("matching iss callback did not issue a session")
	} else if _, err := sessions.Verify(session); err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
}

func TestAuthCallbackRejectsBadState(t *testing.T) {
	h, _ := authAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state=evil", nil)
	req.AddCookie(&http.Cookie{Name: "trstctl_oidc_state", Value: "s-123"}) // mismatch
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("mismatched state = %d, want 400", rec.Code)
	}
}

func cookieValue(cookies []*http.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func callbackFromLogin(t *testing.T, cookies []*http.Cookie, code string) *http.Request {
	t.Helper()
	state := cookieValue(cookies, "trstctl_oidc_state")
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	for _, name := range []string{"trstctl_oidc_prelogin", "trstctl_oidc_state", "trstctl_oidc_nonce", "trstctl_oidc_pkce"} {
		req.AddCookie(&http.Cookie{Name: name, Value: cookieValue(cookies, name)})
	}
	return req
}

func callbackFromLoginWithIss(t *testing.T, cookies []*http.Cookie, code, iss string) *http.Request {
	t.Helper()
	req := callbackFromLogin(t, cookies, code)
	q := req.URL.Query()
	q.Set("iss", iss)
	req.URL.RawQuery = q.Encode()
	return req
}

func TestAuthMeReturnsSessionPrincipal(t *testing.T) {
	h, sessions := authAPI(t)
	tok, err := sessions.Issue("user-1", testTenant, "u@example.test", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-trstctl_session", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me = %d, want 200", rec.Code)
	}
	var body struct {
		Subject     string   `json:"subject"`
		TenantID    string   `json:"tenant_id"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode me body: %v", err)
	}
	if body.Subject != "user-1" || body.TenantID != testTenant {
		t.Errorf("me principal = subject %q tenant %q", body.Subject, body.TenantID)
	}
	if !testStringSetHas(body.Roles, "viewer") {
		t.Errorf("me roles = %v, want viewer", body.Roles)
	}
	for _, want := range []string{"certs:read", "discovery:read", "profiles:read"} {
		if !testStringSetHas(body.Permissions, want) {
			t.Errorf("me permissions = %v, want %q", body.Permissions, want)
		}
	}
	for _, denied := range []string{"audit:read", "certs:request"} {
		if testStringSetHas(body.Permissions, denied) {
			t.Errorf("me permissions = %v, did not want %q", body.Permissions, denied)
		}
	}
}

func TestAuthMeRejectsRevokedServerSideSession(t *testing.T) {
	h, sessions := authAPI(t)
	tok, err := sessions.Issue("user-1", testTenant, "u@example.test", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Verify(tok)
	if err != nil {
		t.Fatalf("Verify before revoke: %v", err)
	}
	if err := sessions.Revoke(sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-trstctl_session", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("me with revoked session = %d, want 401", rec.Code)
	}
}

func testStringSetHas(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestOIDCBackChannelLogoutRevokesSubjectSessions(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sk, err := jose.GenerateRSASigningKey("idp-bcl")
	if err != nil {
		t.Fatal(err)
	}
	cfg, sessions := authConfig()
	verifier := auth.OIDCLogoutVerifier{
		Issuer: testOIDCIssuer, ClientID: "trstctl-ui", Keys: sk.JWKS(),
		Replay: auth.NewLogoutReplayCache(), Now: func() time.Time { return now },
	}
	cfg.VerifyOIDCLogoutToken = verifier.Verify
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	user1a, _ := sessions.Issue("user-1", testTenant, "u1@example.test", []string{"viewer"})
	user1b, _ := sessions.Issue("user-1", testTenant, "u1@example.test", []string{"viewer"})
	user2, _ := sessions.Issue("user-2", testTenant, "u2@example.test", []string{"viewer"})
	raw := logoutToken(t, sk, map[string]any{
		"iss": testOIDCIssuer, "aud": "trstctl-ui", "sub": "user-1", "jti": "logout-1",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, logoutRequest(raw))
	if rec.Code != http.StatusOK {
		t.Fatalf("back-channel logout = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	for _, tok := range []string{user1a, user1b} {
		if _, err := sessions.Verify(tok); !errors.Is(err, auth.ErrSessionRevoked) {
			t.Fatalf("subject session verify err = %v, want ErrSessionRevoked", err)
		}
	}
	if _, err := sessions.Verify(user2); err != nil {
		t.Fatalf("unrelated subject session was revoked: %v", err)
	}
}

func TestOIDCBackChannelLogoutRejectsReplayAndForgery(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sk, err := jose.GenerateRSASigningKey("idp-bcl")
	if err != nil {
		t.Fatal(err)
	}
	other, err := jose.GenerateRSASigningKey("other")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := authConfig()
	verifier := auth.OIDCLogoutVerifier{
		Issuer: testOIDCIssuer, ClientID: "trstctl-ui", Keys: sk.JWKS(),
		Replay: auth.NewLogoutReplayCache(), Now: func() time.Time { return now },
	}
	cfg.VerifyOIDCLogoutToken = verifier.Verify
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	raw := logoutToken(t, sk, map[string]any{
		"iss": testOIDCIssuer, "aud": "trstctl-ui", "sub": "user-1", "jti": "logout-replay",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	})
	first := httptest.NewRecorder()
	h.ServeHTTP(first, logoutRequest(raw))
	if first.Code != http.StatusOK {
		t.Fatalf("first back-channel logout = %d, want 200", first.Code)
	}
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, logoutRequest(raw))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed back-channel logout = %d, want 400", replay.Code)
	}
	forged := logoutToken(t, other, map[string]any{
		"iss": testOIDCIssuer, "aud": "trstctl-ui", "sub": "user-1", "jti": "logout-forged",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, logoutRequest(forged))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged back-channel logout = %d, want 401", rec.Code)
	}
}

func logoutToken(t *testing.T, sk *jose.SigningKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sk.Sign(payload)
	if err != nil {
		t.Fatalf("sign logout token: %v", err)
	}
	return tok
}

func logoutRequest(raw string) *http.Request {
	body := strings.NewReader(url.Values{"logout_token": {raw}}.Encode())
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/back-channel-logout", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestAuthMeUnauthenticated(t *testing.T) {
	h, _ := authAPI(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("me without session = %d, want 401", rec.Code)
	}
}

func TestAuthLogoutClearsSession(t *testing.T) {
	h, _ := authAPI(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", rec.Code)
	}
	var clearedSession, clearedCSRF bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-trstctl_session" && c.MaxAge < 0 {
			clearedSession = true
		}
		if c.Name == "trstctl_csrf" && c.MaxAge < 0 {
			clearedCSRF = true
		}
	}
	if !clearedSession {
		t.Error("logout should clear the session cookie")
	}
	if !clearedCSRF {
		t.Error("logout should clear the CSRF cookie")
	}
}
