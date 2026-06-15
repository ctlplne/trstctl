package api_test

// PROTECT track (sprint R11): the RED-002 keystone guard. The audit found that the
// scary attack chains are all neutralized today by ONE property: the served API is
// fail-closed — resolvePrincipal authenticates only a hashed API token or a verified
// OIDC session, and the route guard 401s every permission-scoped route when no
// principal resolves. The insecure header-trust resolver is test-only and DCE'd from
// the binary (proven separately by TestProductionBinaryDoesNotLinkHeaderTrust).
//
// This locks the fail-closed DEFAULT behavior so it cannot regress: a freshly-built
// API with no auth wired and no token store must reject every permission-scoped route
// (1) with no credentials, (2) with a forged Bearer tt_... token, and (3) with forged
// client identity headers — exactly the RED-002 acceptance ("GET /api/v1/owners on a
// fresh binary -> 401; with any forged Bearer tt_... -> 401"). It changes NO
// behavior; it fails if the guard ever fails-open.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trustctl.io/trustctl/internal/api"
	"trustctl.io/trustctl/internal/auth"
)

// permScopedGETProbes are concrete (no path-param) permission-scoped GET routes of
// the served API — the routes the guard must protect. They are asserted to be real
// served routes by TestFailClosedProbesAreRealRoutes below, so this list cannot
// silently go stale.
var permScopedGETProbes = []string{
	"/api/v1/owners",
	"/api/v1/issuers",
	"/api/v1/identities",
	"/api/v1/certificates",
	"/api/v1/profiles",
	"/api/v1/audit/events",
	"/api/v1/audit/export",
	"/api/v1/graph",
	"/api/v1/risk/credentials",
	"/api/v1/agents",
}

// freshServedAPI builds the API the way a default deployment would before any token
// is provisioned or OIDC is configured: no store, no idempotency, no orchestrator,
// no WithAuth. This is the fail-closed baseline.
func freshServedAPI() http.Handler { return api.New(nil, nil, nil) }

// TestFailClosedProbesAreRealRoutes binds the probe list to the route table: every
// probed path must be a real served GET route, so a future rename cannot make the
// fail-closed assertions silently probe nonexistent paths (which a router might 404,
// masking a regression).
func TestFailClosedProbesAreRealRoutes(t *testing.T) {
	served := map[string]bool{}
	for _, rt := range api.New(nil, nil, nil).Routes() {
		if rt.Method == http.MethodGet {
			served[rt.Path] = true
		}
	}
	for _, p := range permScopedGETProbes {
		if !served[p] {
			t.Errorf("RED-002: probe %q is not a served GET route anymore; update the fail-closed probe list", p)
		}
	}
}

// TestServedAPIIsFailClosedWithoutCredentials is the RED-002 lock (no creds): every
// permission-scoped GET route on a fresh served API answers 401 when the request
// carries no Authorization and no session cookie.
func TestServedAPIIsFailClosedWithoutCredentials(t *testing.T) {
	h := freshServedAPI()
	for _, p := range permScopedGETProbes {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("RED-002: GET %s without credentials = %d, want 401 (the served guard must fail closed)", p, rec.Code)
		}
	}
}

// TestServedAPIRejectsForgedBearerToken is the RED-002 lock (forged token): a forged
// Bearer tt_... token must NOT authenticate. On a fresh API with no token store the
// resolver cannot look the token up; either way the route answers 401, never 200.
func TestServedAPIRejectsForgedBearerToken(t *testing.T) {
	h := freshServedAPI()
	// Several forged tokens that carry the real tt_ prefix the resolver recognizes.
	forged := []string{
		auth.TokenPrefix + "AAAAAAAAAAAAAAAAAAAAAAAA",
		auth.TokenPrefix + "deadbeefdeadbeefdeadbeef",
		auth.TokenPrefix + "forged-admin-everything",
	}
	for _, p := range permScopedGETProbes {
		for _, tok := range forged {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				t.Errorf("RED-002: GET %s with forged Bearer %q returned 200 — the served guard authenticated a forged token", p, tok)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("RED-002: GET %s with forged Bearer %q = %d, want 401", p, tok, rec.Code)
			}
		}
	}
}

// TestServedAPIRejectsClientSuppliedIdentityHeaders is the RED-002 lock against the
// header-trust path: the default resolver must NEVER trust a client-supplied identity
// header. A request carrying these but no real credential must still be 401 — the
// insecure header resolver is test-only and not wired into the served API.
func TestServedAPIRejectsClientSuppliedIdentityHeaders(t *testing.T) {
	h := freshServedAPI()
	for _, p := range permScopedGETProbes {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
		req.Header.Set("X-Tenant", "11111111-1111-1111-1111-111111111111")
		req.Header.Set("X-User", "attacker")
		req.Header.Set("X-Roles", "admin")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("RED-002: GET %s with forged identity headers = %d, want 401 (the served resolver must not trust client headers)", p, rec.Code)
		}
	}
}

// TestPublicSpecRouteStaysReachable is the consistency anchor: the guard must
// distinguish public from protected. The OpenAPI document is the one GET route with
// no required permission, so it must remain reachable without credentials — proving
// the 401s above come from the permission guard, not a blanket deny.
func TestPublicSpecRouteStaysReachable(t *testing.T) {
	h := freshServedAPI()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("RED-002: GET /api/v1/openapi.json (public) = %d, want 200; the guard must not blanket-deny", rec.Code)
	}
}
