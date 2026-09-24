// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
)

func samlReturnConfig(t *testing.T) (api.AuthConfig, *auth.SessionIssuer) {
	t.Helper()
	cfg, sessions := authConfig()
	cfg.SAMLEnabled = true
	cfg.LoginRedirect = "/default-after-login"
	cfg.SAMLLoginRedirect = func(state string) (string, string, error) {
		return "https://idp.example.test/sso?RelayState=" + url.QueryEscape(state), "request-1", nil
	}
	cfg.VerifySAMLResponse = func(_ *http.Request, ids []string) (auth.Claims, error) {
		if len(ids) != 1 || ids[0] != "request-1" {
			t.Fatalf("SAML request correlation lost: %v", ids)
		}
		return auth.Claims{Subject: "saml-user"}, nil
	}
	cfg.ResolveSAMLTenant = cfg.ResolveTenant
	return cfg, sessions
}

func TestSAMLReturnContextRejectsTamperingBeforeAssertionVerification(t *testing.T) {
	for _, name := range []string{"missing first", "missing second", "duplicate", "tampered", "oversized", "cross attempt", "wrong key", "expired"} {
		t.Run(name, func(t *testing.T) {
			cfg, sessions := samlReturnConfig(t)
			clock := time.Unix(2000000000, 0)
			sessions.Now = func() time.Time { return clock }
			verified := false
			cfg.VerifySAMLResponse = func(_ *http.Request, _ []string) (auth.Claims, error) {
				verified = true
				return auth.Claims{Subject: "saml-user"}, nil
			}
			h := api.New(nil, nil, nil, api.WithAuth(cfg))
			login := httptest.NewRecorder()
			h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/saml/login?return_to=%2Fcertificates", nil))
			if login.Code != http.StatusFound {
				t.Fatalf("login status=%d", login.Code)
			}
			cookies := login.Result().Cookies()
			modified := make([]*http.Cookie, 0, len(cookies)+1)
			for _, cookie := range cookies {
				if (name == "missing first" && cookie.Name == "trstctl_saml_return_0") || (name == "missing second" && cookie.Name == "trstctl_saml_return_1") {
					continue
				}
				if cookie.Name == "trstctl_saml_return_0" {
					switch name {
					case "duplicate":
						modified = append(modified, cookie)
					case "tampered":
						cookie.Value = "A" + cookie.Value[1:]
					case "oversized":
						cookie.Value = strings.Repeat("a", 3501)
					}
				}
				if name == "cross attempt" && cookie.Name == "trstctl_saml_state" {
					cookie.Value = "another-attempt"
				}
				modified = append(modified, cookie)
			}
			if name == "expired" {
				clock = clock.Add(10 * time.Minute)
			}
			if name == "wrong key" {
				cfg.Sessions = auth.NewSessionIssuer([]byte(strings.Repeat("x", 32)), time.Hour)
				cfg.Sessions.Now = func() time.Time { return clock }
				h = api.New(nil, nil, nil, api.WithAuth(cfg))
			}
			completed := httptest.NewRecorder()
			h.ServeHTTP(completed, samlReturnCallback(modified))
			if completed.Code != http.StatusBadRequest || verified || cookieValue(completed.Result().Cookies(), "__Host-trstctl_session") != "" {
				t.Fatalf("untrusted context: status=%d assertion verifier called=%v; want400 before verification/session", completed.Code, verified)
			}
		})
	}
}

func TestSAMLReturnCookiesAndIDPDefault(t *testing.T) {
	for _, secure := range []bool{true, false} {
		cfg, _ := samlReturnConfig(t)
		cfg.Secure = secure
		h := api.New(nil, nil, nil, api.WithAuth(cfg))
		login := httptest.NewRecorder()
		h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/saml/login?return_to=%2Fcertificates", nil))
		found := 0
		for _, cookie := range login.Result().Cookies() {
			if !strings.HasPrefix(cookie.Name, "trstctl_saml_return_") {
				continue
			}
			found++
			wantSameSite := http.SameSiteLaxMode
			if secure {
				wantSameSite = http.SameSiteNoneMode
			}
			if cookie.Secure != secure || !cookie.HttpOnly || cookie.SameSite != wantSameSite || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 600 || cookie.Value == "" || len(cookie.String()) > 4096 {
				t.Fatal("return cookie must retain bounded, host-only, ten-minute SAML POST policy")
			}
		}
		if found != 2 {
			t.Fatalf("return cookie count=%d, want2", found)
		}
		completed := httptest.NewRecorder()
		h.ServeHTTP(completed, samlReturnCallback(login.Result().Cookies()))
		if completed.Code != http.StatusFound {
			t.Fatalf("callback status=%d", completed.Code)
		}
		cleared := 0
		for _, cookie := range completed.Result().Cookies() {
			if strings.HasPrefix(cookie.Name, "trstctl_saml_return_") && cookie.MaxAge < 0 {
				cleared++
			}
			if (cookie.Name == "__Host-trstctl_session" || cookie.Name == "trstctl_session" || cookie.Name == "trstctl_csrf") && cookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("authenticated cookies must remain Strict")
			}
		}
		if cleared != 2 {
			t.Fatal("successful ACS must clear both return cookies")
		}

		// IdP-initiated login has no RelayState. Stale context and unbound form
		// or query destinations must never override its configured default.
		cfg.VerifySAMLResponse = func(_ *http.Request, ids []string) (auth.Claims, error) {
			if len(ids) != 0 {
				t.Fatal("IdP-initiated login acquired an unrelated request ID")
			}
			return auth.Claims{Subject: "idp-user"}, nil
		}
		h = api.New(nil, nil, nil, api.WithAuth(cfg))
		form := url.Values{"SAMLResponse": {"fixture-assertion"}, "return_to": {"/unbound-form"}}
		req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs?return_to=%2Funbound-query", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range login.Result().Cookies() {
			req.AddCookie(cookie)
		}
		idp := httptest.NewRecorder()
		h.ServeHTTP(idp, req)
		if idp.Code != http.StatusFound || idp.Header().Get("Location") != cfg.LoginRedirect {
			t.Fatal("IdP-initiated login must preserve configured default")
		}
	}
}

func samlReturnCallback(cookies []*http.Cookie) *http.Request {
	form := url.Values{
		"RelayState":   {cookieValue(cookies, "trstctl_saml_state")},
		"SAMLResponse": {"fixture-assertion"},
		"return_to":    {"https://unbound-form.example/"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs?return_to=https%3A%2F%2Funbound-query.example%2F", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		if cookie.MaxAge >= 0 {
			req.AddCookie(cookie)
		}
	}
	return req
}

func TestSAMLLoginResumesBoundLocalPathAcrossInstances(t *testing.T) {
	unicodeTarget := "/" + strings.Repeat("é", 2047)
	u, err := url.Parse(unicodeTarget)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, input, want string }{
		{"page query and fragment", "/certificates?owner=a%20b&expiry=30d#inventory", "/certificates?owner=a%20b&expiry=30d#inventory"},
		{"home override", "/", "/"},
		{"full input bound", "/" + strings.Repeat("a", 4095), "/" + strings.Repeat("a", 4095)},
		{"unicode within input bound", unicodeTarget, u.String()},
		{"no override", "", "/default-after-login"},
		{"absolute", "https://outside.example/", "/default-after-login"},
		{"protocol relative", "//outside.example/", "/default-after-login"},
		{"encoded slash", "/%2foutside.example/", "/default-after-login"},
		{"encoded backslash", "/%5coutside.example/", "/default-after-login"},
		{"control in query", "/policy?x=%0d%0aLocation:outside", "/default-after-login"},
		{"encoded auth", "/%61uth/login", "/default-after-login"},
		{"normalized auth", "/x/../auth/login", "/default-after-login"},
		{"malformed escape", "/%", "/default-after-login"},
		{"oversized", "/" + strings.Repeat("a", 4096), "/default-after-login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			startConfig, _ := samlReturnConfig(t)
			callbackConfig, sessions := samlReturnConfig(t)
			start := api.New(nil, nil, nil, api.WithAuth(startConfig))
			finish := api.New(nil, nil, nil, api.WithAuth(callbackConfig))
			login := httptest.NewRecorder()
			start.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/saml/login?return_to="+url.QueryEscape(tc.input), nil))
			if login.Code != http.StatusFound {
				t.Fatalf("start status = %d", login.Code)
			}
			idp, err := url.Parse(login.Header().Get("Location"))
			if err != nil || idp.Query().Get("return_to") != "" {
				t.Fatal("return target must not be sent to the IdP")
			}
			for _, cookie := range login.Result().Cookies() {
				if len(cookie.String()) > 4096 {
					t.Fatalf("%s exceeds the browser cookie wire limit", cookie.Name)
				}
			}
			completed := httptest.NewRecorder()
			finish.ServeHTTP(completed, samlReturnCallback(login.Result().Cookies()))
			if completed.Code != http.StatusFound || completed.Header().Get("Location") != tc.want {
				t.Fatalf("callback status=%d destination matched=%v; want302 and the bound destination", completed.Code, completed.Header().Get("Location") == tc.want)
			}
			session, err := sessions.Verify(cookieValue(completed.Result().Cookies(), "__Host-trstctl_session"))
			if err != nil || session.TenantID != testTenant || session.Subject != "saml-user" {
				t.Fatalf("callback did not create the mapped SAML session: %v", err)
			}
		})
	}
}
