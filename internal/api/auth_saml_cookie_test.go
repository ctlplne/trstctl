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

func TestSAMLLoginCookiesSupportCrossSitePOSTWithoutRelaxingOIDC(t *testing.T) {
	cfg, _ := authConfig()
	cfg.SAMLEnabled = true
	cfg.SAMLLoginRedirect = func(state string) (string, string, error) {
		return "https://idp.example.test/sso?RelayState=" + url.QueryEscape(state), "request-1", nil
	}
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	for _, tc := range []struct {
		path     string
		names    []string
		sameSite http.SameSite
	}{
		{"/auth/saml/login", []string{"trstctl_saml_state", "trstctl_saml_request_id"}, http.SameSiteNoneMode},
		{"/auth/login", []string{"trstctl_oidc_state", "trstctl_oidc_nonce"}, http.SameSiteLaxMode},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != http.StatusFound {
				t.Fatalf("login = %d, want redirect", rec.Code)
			}
			cookies := map[string]*http.Cookie{}
			for _, c := range rec.Result().Cookies() {
				cookies[c.Name] = c
			}
			for _, name := range tc.names {
				c := cookies[name]
				if c == nil {
					t.Fatalf("missing %s", name)
				}
				if c.SameSite != tc.sameSite || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.MaxAge != 600 || c.Value == "" {
					t.Errorf("%s policy: SameSite=%v Secure=%v HttpOnly=%v Path=%q Domain=%q MaxAge=%d; want scoped, secure ten-minute cookie with SameSite=%v", name, c.SameSite, c.Secure, c.HttpOnly, c.Path, c.Domain, c.MaxAge, tc.sameSite)
				}
			}
		})
	}
}

func TestSAMLPOSTCookiePolicyPreservesStateBindingAndStrictSession(t *testing.T) {
	for _, tc := range []struct {
		name, state, requestID string
		want                   int
	}{
		{"missing state", "", "request-1", http.StatusBadRequest},
		{"wrong state", "attacker-state", "request-1", http.StatusBadRequest},
		{"missing request ID", "server-state", "", http.StatusBadRequest},
		{"bound response", "server-state", "request-1", http.StatusFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := authConfig()
			verified := false
			cfg.VerifySAMLResponse = func(_ *http.Request, ids []string) (auth.Claims, error) {
				verified = true
				if len(ids) != 1 || ids[0] != "request-1" {
					t.Fatalf("verifier request binding = %v", ids)
				}
				return auth.Claims{Subject: "saml-user"}, nil
			}
			cfg.ResolveSAMLTenant = cfg.ResolveTenant
			h := api.New(nil, nil, nil, api.WithAuth(cfg))
			form := url.Values{"RelayState": {"server-state"}, "SAMLResponse": {"fixture-assertion"}}
			req := httptest.NewRequest(http.MethodPost, "/auth/saml/acs", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.state != "" {
				req.AddCookie(&http.Cookie{Name: "trstctl_saml_state", Value: tc.state}) // #nosec G124 -- request cookie for the local handler fixture (CWE-1004)
			}
			if tc.requestID != "" {
				req.AddCookie(&http.Cookie{Name: "trstctl_saml_request_id", Value: tc.requestID}) // #nosec G124 -- request cookie for the local handler fixture (CWE-1004)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want || verified != (tc.want == http.StatusFound) {
				t.Fatalf("ACS status=%d verified=%v, want status=%d and verification only after state binding", rec.Code, verified, tc.want)
			}
			if tc.want != http.StatusFound {
				return
			}
			cookies := map[string]*http.Cookie{}
			for _, c := range rec.Result().Cookies() {
				cookies[c.Name] = c
			}
			for _, name := range []string{"__Host-trstctl_session", "trstctl_csrf"} {
				c := cookies[name]
				if c == nil || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Value == "" || c.HttpOnly != (name == "__Host-trstctl_session") {
					t.Fatalf("%s must preserve the strict session/CSRF cookie policy", name)
				}
			}
			for _, name := range []string{"trstctl_saml_state", "trstctl_saml_request_id"} {
				if c := cookies[name]; c == nil || c.MaxAge >= 0 {
					t.Fatalf("successful ACS must clear %s", name)
				}
			}
		})
	}
}

func TestSAMLPlaintextDevelopmentRetainsLaxCorrelationCookies(t *testing.T) {
	cfg, _ := authConfig()
	cfg.Secure = false
	cfg.SAMLEnabled = true
	cfg.SAMLLoginRedirect = func(state string) (string, string, error) {
		return "https://idp.example.test/sso?RelayState=" + url.QueryEscape(state), "request-1", nil
	}
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/saml/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d, want redirect", rec.Code)
	}
	cookies := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		cookies[c.Name] = c
	}
	for _, name := range []string{"trstctl_saml_state", "trstctl_saml_request_id"} {
		c := cookies[name]
		if c == nil || c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Path != "/" || c.MaxAge != 600 || c.Value == "" {
			t.Fatalf("%s must retain the scoped, HttpOnly, ten-minute Lax policy in plaintext development", name)
		}
	}
}
