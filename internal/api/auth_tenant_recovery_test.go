// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
)

func TestOIDCUnmappedAccountHasSafeBrowserRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, accept string
		browser      bool
	}{
		{"browser document", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", true},
		{"HTML explicitly selected", "text/html", true},
		{"API problem", "application/problem+json", false},
		{"unspecified API", "", false},
		{"HTML refused", "text/html;q=0,application/json", false},
		{"JSON preferred", "text/html;q=0.5,application/json", false},
		{"malformed HTML quality", "text/html;q=invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := authConfig()
			cfg.ResolveTenant = func(auth.Claims) (string, []string, error) { return "", nil, auth.ErrNoTenant }
			h := api.New(nil, nil, nil, api.WithAuth(cfg))
			login := httptest.NewRecorder()
			h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
			req := callbackFromLogin(t, login.Result().Cookies(), "good-code")
			req.Header.Set("Accept", tc.accept)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if cookieValue(rec.Result().Cookies(), "__Host-trstctl_session") != "" {
				t.Fatal("unmapped account received a session")
			}
			if tc.browser {
				if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?error=tenant_access_not_configured" {
					t.Fatalf("browser recovery = %d %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
				}
				if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
					t.Fatal("callback recovery must not cache or forward its query")
				}
				for _, name := range []string{"trstctl_oidc_prelogin", "trstctl_oidc_state", "trstctl_oidc_nonce", "trstctl_oidc_pkce"} {
					cleared := false
					for _, c := range rec.Result().Cookies() {
						if c.Name == name && c.Value == "" && c.MaxAge < 0 {
							cleared = true
						}
					}
					if !cleared {
						t.Errorf("consumed login cookie %s not cleared", name)
					}
				}
				if strings.Contains(rec.Body.String(), "good-code") || strings.Contains(rec.Body.String(), "user-1") {
					t.Fatal("callback credentials or account identity leaked to recovery response")
				}
			} else if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("Content-Type"), "application/problem+json") || !strings.Contains(rec.Body.String(), "no tenant for this user") {
				t.Fatalf("API failure = %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}
