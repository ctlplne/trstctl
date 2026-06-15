package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/api"
	"trustctl.io/trustctl/internal/auth"
)

const testTenant = "11111111-1111-1111-1111-111111111111"

func authConfig() (api.AuthConfig, *auth.SessionIssuer) {
	sessions := auth.NewSessionIssuer([]byte("test-secret-0123456789abcdef0123"), time.Hour)
	cfg := api.AuthConfig{
		AuthEndpoint:  "https://idp.example.test/authorize",
		ClientID:      "trustctl-ui",
		RedirectURI:   "https://app.example.test/auth/callback",
		DefaultTenant: testTenant,
		Exchange: func(_ context.Context, code string) (string, error) {
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
	if !strings.Contains(loc, "state=") || !strings.Contains(loc, "nonce=") || !strings.Contains(loc, "client_id=trustctl-ui") {
		t.Errorf("authorize URL missing params: %q", loc)
	}
	cookies := rec.Result().Cookies()
	var sawState, sawNonce bool
	for _, c := range cookies {
		if c.Name == "trustctl_oidc_state" {
			sawState = true
		}
		if c.Name == "trustctl_oidc_nonce" {
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

func TestAuthCallbackEstablishesSession(t *testing.T) {
	h, sessions := authAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state=s-123", nil)
	req.AddCookie(&http.Cookie{Name: "trustctl_oidc_state", Value: "s-123"})
	req.AddCookie(&http.Cookie{Name: "trustctl_oidc_nonce", Value: "n-123"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "trustctl_session" {
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
}

func TestAuthCallbackRejectsBadState(t *testing.T) {
	h, _ := authAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state=evil", nil)
	req.AddCookie(&http.Cookie{Name: "trustctl_oidc_state", Value: "s-123"}) // mismatch
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("mismatched state = %d, want 400", rec.Code)
	}
}

func TestAuthMeReturnsSessionPrincipal(t *testing.T) {
	h, sessions := authAPI(t)
	tok, err := sessions.Issue("user-1", testTenant, "u@example.test", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "trustctl_session", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "user-1") || !strings.Contains(rec.Body.String(), testTenant) {
		t.Errorf("me body = %s", rec.Body.String())
	}
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
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "trustctl_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout should clear the session cookie")
	}
}
