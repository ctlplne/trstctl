package projections_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// prodAPIServer builds the API the way the production composition root does: with
// NO insecure header resolver, so the default authenticated resolver (bearer API
// token or OIDC session, else 401) is in force. This is the assembled posture B1
// is about.
func prodAPIServer(t *testing.T, opts ...api.Option) (*httptest.Server, *store.Store) {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)), opts...)
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv, s
}

// mintTokenFor mints a real API token for an arbitrary tenant with the given
// scopes, returning the raw bearer value.
func mintTokenFor(t *testing.T, s *store.Store, tenant string, scopes ...string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: tenant, TokenHash: hash, Subject: "ci-bot", Scopes: scopes,
	}); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	return raw
}

// TestHeaderOnlyRequestIsRejected is the disconfirming test the audit said was
// missing (B1): with the production resolver, a request that supplies only
// identity HEADERS (X-Tenant-ID + X-Roles: admin) and no verified credential is
// rejected with 401 — the header-trust path is gone.
func TestHeaderOnlyRequestIsRejected(t *testing.T) {
	srv, _ := prodAPIServer(t)

	// A read and a write, both with admin headers and no token/session.
	for _, m := range []struct {
		method, path string
	}{
		{"GET", "/api/v1/owners"},
		{"POST", "/api/v1/owners"},
	} {
		req, _ := http.NewRequest(m.method, srv.URL+m.path, strings.NewReader(`{"kind":"service","name":"x"}`))
		req.Header.Set("X-Tenant-ID", tenantA)
		req.Header.Set("X-Roles", "admin")
		req.Header.Set("X-Subject", "attacker")
		req.Header.Set("Idempotency-Key", "k1")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with only identity headers = %d, want 401 (header trust must be gone): %s", m.method, m.path, resp.StatusCode, body)
		}
	}
}

// TestTokenForTenantACannotReachTenantB: an authenticated tenant-A token cannot
// read another tenant's data, even when it forges X-Tenant-ID for tenant B — the
// token's own tenant is authoritative (RLS + authenticated tenant).
func TestTokenForTenantACannotReachTenantB(t *testing.T) {
	srv, s := prodAPIServer(t)
	tokenA := mintTokenFor(t, s, tenantA, "*")
	tokenB := mintTokenFor(t, s, tenantB, "*")

	// Tenant B creates an owner.
	if st, _, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantB, bearer: tokenB, idem: "b1", body: map[string]any{"kind": "service", "name": "beta-owner"}}); st != http.StatusCreated {
		t.Fatalf("tenant B create owner = %d: %s", st, body)
	}
	// Tenant B sees it.
	if _, _, body := do(t, srv, "GET", "/api/v1/owners", reqOpts{tenant: tenantB, bearer: tokenB}); !strings.Contains(string(body), "beta-owner") {
		t.Fatalf("tenant B should see its own owner: %s", body)
	}
	// Tenant A's token, even claiming X-Tenant-ID = tenant B, sees none of B's data.
	st, _, body := do(t, srv, "GET", "/api/v1/owners", reqOpts{tenant: tenantB, bearer: tokenA})
	if st != http.StatusOK {
		t.Fatalf("tenant A list = %d: %s", st, body)
	}
	if strings.Contains(string(body), "beta-owner") {
		t.Errorf("tenant A token read tenant B's data through a forged X-Tenant-ID header: %s", body)
	}
}

// TestOIDCSessionAuthorizesAPIByRoles: a verified OIDC session cookie authorizes
// API calls per the roles carried in the session — the web login is no longer
// cosmetic relative to the API.
func TestOIDCSessionAuthorizesAPIByRoles(t *testing.T) {
	sessions := auth.NewSessionIssuer([]byte("test-session-secret-0123456789ab"), time.Hour)
	cfg := api.AuthConfig{Sessions: sessions, DefaultTenant: tenantA, DefaultRoles: []string{"operator"}}
	srv, _ := prodAPIServer(t, api.WithAuth(cfg))

	// An operator session may write.
	opSess, err := sessions.Issue("alice", tenantA, "alice@acme.test", []string{"operator"})
	if err != nil {
		t.Fatal(err)
	}
	if st, body := sessionReq(t, srv, "POST", "/api/v1/owners", opSess, `{"kind":"service","name":"from-session"}`); st != http.StatusCreated {
		t.Fatalf("operator session POST owners = %d, want 201: %s", st, body)
	}

	// A viewer session may read but not write.
	viewerSess, err := sessions.Issue("bob", tenantA, "bob@acme.test", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := sessionReq(t, srv, "GET", "/api/v1/owners", viewerSess, ""); st != http.StatusOK {
		t.Errorf("viewer session GET owners = %d, want 200", st)
	}
	if st, _ := sessionReq(t, srv, "POST", "/api/v1/owners", viewerSess, `{"kind":"service","name":"nope"}`); st != http.StatusForbidden {
		t.Errorf("viewer session POST owners = %d, want 403", st)
	}
}

// sessionReq issues an HTTP request authenticated by a session cookie.
func sessionReq(t *testing.T, srv *httptest.Server, method, path, session, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, srv.URL+path, r)
	req.AddCookie(&http.Cookie{Name: "trstctl_session", Value: session})
	if method != http.MethodGet {
		req.Header.Set("Idempotency-Key", "sess-"+method+path)
		req.Header.Set("Content-Type", "application/json")
		// SEC-007 double-submit CSRF: a session-authenticated mutation must carry a
		// matching trstctl_csrf cookie + X-CSRF-Token header (the SPA reads the
		// non-HttpOnly cookie set at login and echoes it in the header). enforceCSRF
		// only checks the two are equal, so a matching pair is what a real browser sends.
		const csrf = "test-csrf-token-double-submit"
		req.AddCookie(&http.Cookie{Name: "trstctl_csrf", Value: csrf})
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}
