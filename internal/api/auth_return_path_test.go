// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
)

func TestOIDCLoginResumesBoundLocalPath(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"page query and fragment", "/policy?tab=rules&owner=a%20b#history", "/policy?tab=rules&owner=a%20b#history"},
		{"exact resource", "/identities?identity=a7f7973c-0acc-55d1-92c7-af7c9f8729ee", "/identities?identity=a7f7973c-0acc-55d1-92c7-af7c9f8729ee"},
		{"home", "/", "/"},
		{"no override", "", "/default-after-login"},
		{"absolute", "https://outside.example/", "/default-after-login"},
		{"protocol relative", "//outside.example/", "/default-after-login"},
		{"backslash", "/\\outside.example/", "/default-after-login"},
		{"encoded backslash", "/%5coutside.example/", "/default-after-login"},
		{"encoded slash", "/%2foutside.example/", "/default-after-login"},
		{"encoded control", "/%0a/outside.example", "/default-after-login"},
		{"control in query", "/policy?x=%0d%0aLocation:outside", "/default-after-login"},
		{"relative", "policy", "/default-after-login"},
		{"scheme", "javascript:alert(1)", "/default-after-login"},
		{"login loop", "/login?return_to=/policy", "/default-after-login"},
		{"login trailing slash", "/login/", "/default-after-login"},
		{"case folded login", "/LOGIN", "/default-after-login"},
		{"case folded auth", "/AUTH/login", "/default-after-login"},
		{"auth callback", "/auth/callback?code=untrusted", "/default-after-login"},
		{"normalized auth path", "/x/../auth/login", "/default-after-login"},
		{"encoded auth path", "/%61uth/login", "/default-after-login"},
		{"oversized", "/policy?x=" + strings.Repeat("a", 4096), "/default-after-login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, sessions := authConfig()
			cfg.LoginRedirect = "/default-after-login"
			h := api.New(nil, nil, nil, api.WithAuth(cfg))
			login := httptest.NewRecorder()
			h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(tc.input), nil))
			if login.Code != 302 {
				t.Fatalf("login: %d %s", login.Code, login.Body.String())
			}
			provider, err := url.Parse(login.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if provider.Query().Get("return_to") != "" {
				t.Fatal("UI target leaked to IdP")
			}
			callback := callbackFromLogin(t, login.Result().Cookies(), "good-code")
			q := callback.URL.Query()
			q.Set("return_to", "https://callback-attacker.example/")
			callback.URL.RawQuery = q.Encode()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, callback)
			if rec.Code != 302 || rec.Header().Get("Location") != tc.want {
				t.Fatalf("callback = %d %q, want302 %q", rec.Code, rec.Header().Get("Location"), tc.want)
			}
			session, err := sessions.Verify(cookieValue(rec.Result().Cookies(), "__Host-trstctl_session"))
			if err != nil || session.TenantID != testTenant {
				t.Fatalf("session: %+v %v", session, err)
			}
			replay := httptest.NewRecorder()
			h.ServeHTTP(replay, callback)
			if replay.Code != 400 || cookieValue(replay.Result().Cookies(), "__Host-trstctl_session") != "" {
				t.Fatalf("consumed login replay: %d", replay.Code)
			}
		})
	}
}

func TestOIDCUnmappedRecoveryPreservesOnlySafeReturnPath(t *testing.T) {
	cfg, _ := authConfig()
	cfg.ResolveTenant = func(auth.Claims) (string, []string, error) { return "", nil, auth.ErrNoTenant }
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	login := httptest.NewRecorder()
	target := "/policy?tab=rules#history"
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(target), nil))
	req := callbackFromLogin(t, login.Result().Cookies(), "good-code")
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != 303 || location.Path != "/login" || location.Query().Get("error") != "tenant_access_not_configured" || location.Query().Get("return_to") != target {
		t.Fatalf("recovery: %d %s", rec.Code, location)
	}
	if cookieValue(rec.Result().Cookies(), "__Host-trstctl_session") != "" {
		t.Fatal("unmapped account got a session")
	}
	if strings.Contains(location.String(), "good-code") || location.Query().Get("state") != "" {
		t.Fatal("callback credentials leaked")
	}
}
