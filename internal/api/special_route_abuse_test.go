package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
)

func TestSpecialAuthLoginRouteRateLimitedSEC002(t *testing.T) {
	cfg, _ := authConfig()
	h := api.New(nil, nil, nil,
		api.WithAuth(cfg),
		api.WithSpecialRouteAbuseLimits(api.SpecialRouteAbuseLimits{
			Window:            time.Minute,
			Global:            10,
			PerSource:         10,
			PreLoginGlobal:    1,
			PreLoginPerSource: 1,
		}),
	)

	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	firstReq.RemoteAddr = "203.0.113.10:1234"
	h.ServeHTTP(first, firstReq)
	if first.Code != http.StatusFound {
		t.Fatalf("first GET /auth/login = %d, want 302", first.Code)
	}
	if cookieValue(first.Result().Cookies(), "trstctl_oidc_prelogin") == "" {
		t.Fatal("first login did not create a bounded pre-login cookie")
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	secondReq.RemoteAddr = "203.0.113.11:1234"
	h.ServeHTTP(second, secondReq)
	assertSpecialTooManyRequests(t, second, "GET /auth/login")
	if cookieValue(second.Result().Cookies(), "trstctl_oidc_prelogin") != "" {
		t.Fatal("over-budget login created another pre-login cookie")
	}
}

func TestSpecialLDAPLoginRouteRateLimitedSEC002(t *testing.T) {
	cfg, _ := authConfig()
	cfg.LDAPEnabled = true
	ldapCalls := 0
	cfg.VerifyLDAPLogin = func(_ context.Context, username string, password []byte) (auth.Claims, error) {
		ldapCalls++
		return auth.Claims{Subject: username, Email: username + "@example.test"}, nil
	}
	h := api.New(nil, nil, nil,
		api.WithAuth(cfg),
		api.WithSpecialRouteAbuseLimits(api.SpecialRouteAbuseLimits{
			Window:            time.Minute,
			Global:            10,
			PerSource:         1,
			PreLoginGlobal:    10,
			PreLoginPerSource: 10,
		}),
	)

	body := []byte(`{"username":"alice","password":"correct horse"}`)
	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", bytes.NewReader(body))
	firstReq.RemoteAddr = "203.0.113.20:1234"
	firstReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(first, firstReq)
	if first.Code != http.StatusFound {
		t.Fatalf("first POST /auth/ldap/login = %d, want 302: %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", bytes.NewReader(body))
	secondReq.RemoteAddr = "203.0.113.20:5678"
	secondReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(second, secondReq)
	assertSpecialTooManyRequests(t, second, "POST /auth/ldap/login")
	if ldapCalls != 1 {
		t.Fatalf("LDAP verifier calls = %d, want only the first request to bind", ldapCalls)
	}
}

func TestSpecialEnrollBootstrapRouteRateLimitedSEC002(t *testing.T) {
	enroller := &countingSpecialEnroller{}
	h := api.New(nil, nil, nil,
		api.WithAgentEnroller(enroller),
		api.WithSpecialRouteAbuseLimits(api.SpecialRouteAbuseLimits{
			Window:            time.Minute,
			Global:            10,
			PerSource:         10,
			PerToken:          1,
			PerTenant:         10,
			PreLoginGlobal:    10,
			PreLoginPerSource: 10,
		}),
	)

	body, _ := json.Marshal(map[string]string{
		"token": "bootstrap-token",
		"csr":   base64.StdEncoding.EncodeToString([]byte("csr-der")),
	})
	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodPost, "/enroll/bootstrap", bytes.NewReader(body))
	firstReq.RemoteAddr = "203.0.113.30:1234"
	firstReq.Header.Set("Content-Type", "application/json")
	firstReq.Header.Set("X-Tenant-ID", testTenant)
	h.ServeHTTP(first, firstReq)
	if first.Code != http.StatusOK {
		t.Fatalf("first POST /enroll/bootstrap = %d, want 200: %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/enroll/bootstrap", bytes.NewReader(body))
	secondReq.RemoteAddr = "203.0.113.31:1234"
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set("X-Tenant-ID", testTenant)
	h.ServeHTTP(second, secondReq)
	assertSpecialTooManyRequests(t, second, "POST /enroll/bootstrap")
	if enroller.calls != 1 {
		t.Fatalf("bootstrap enroller calls = %d, want only the first request to reach enrollment", enroller.calls)
	}
}

func TestSpecialSCIMUsersRouteRateLimitedSEC002(t *testing.T) {
	token := "scim-secret"
	h := api.New(nil, nil, nil,
		api.WithSCIM(api.SCIMConfig{Enabled: true, Tokens: []api.SCIMToken{{
			Name:      "okta",
			TenantID:  testTenant,
			TokenHash: crypto.SHA256Hex([]byte(token)),
		}}}),
		api.WithSpecialRouteAbuseLimits(api.SpecialRouteAbuseLimits{
			Window:            time.Minute,
			Global:            10,
			PerSource:         10,
			PerToken:          1,
			PerTenant:         10,
			PreLoginGlobal:    10,
			PreLoginPerSource: 10,
		}),
	)

	body := []byte(`{"userName":"alice@example.test","active":true}`)
	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader(body))
	firstReq.RemoteAddr = "203.0.113.40:1234"
	firstReq.Header.Set("Authorization", "Bearer "+token)
	firstReq.Header.Set("Content-Type", "application/scim+json")
	firstReq.Header.Set("Idempotency-Key", "scim-first")
	h.ServeHTTP(first, firstReq)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("first POST /scim/v2/Users = %d, want 503 from missing store after budget check", first.Code)
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader(body))
	secondReq.RemoteAddr = "203.0.113.41:1234"
	secondReq.Header.Set("Authorization", "Bearer "+token)
	secondReq.Header.Set("Content-Type", "application/scim+json")
	secondReq.Header.Set("Idempotency-Key", "scim-second")
	h.ServeHTTP(second, secondReq)
	assertSpecialTooManyRequests(t, second, "POST /scim/v2/Users")
}

type countingSpecialEnroller struct {
	calls int
}

func (e *countingSpecialEnroller) EnrollBootstrap(_ context.Context, _ []byte, _ []byte) ([]byte, error) {
	e.calls++
	return []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"), nil
}

func (e *countingSpecialEnroller) CABundlePEM() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")
}

func assertSpecialTooManyRequests(t *testing.T, rec *httptest.ResponseRecorder, route string) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("%s over budget = %d, want 429: %s", route, rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Fatalf("%s over budget missing Retry-After", route)
	}
}
