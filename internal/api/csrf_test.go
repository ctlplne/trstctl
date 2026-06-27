package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// sessionCookieFor mints a session token (admin role, so authz never blocks) and
// returns it as the session cookie value.
func sessionCookieFor(t *testing.T) (http.Handler, string) {
	t.Helper()
	h, sessions := authAPI(t)
	tok, err := sessions.Issue("user-1", testTenant, "u@example.test", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	return h, tok
}

// mutatingPath is a real served, permission-gated, mutating route. The CSRF gate in
// guard runs after authz and before the handler, so a session-authenticated POST
// here exercises the CSRF check regardless of whether the handler's dependencies
// are wired (an un-wired handler returns 503, not 403 — distinguishable from a CSRF
// rejection).
const mutatingPath = "/api/v1/agents/enrollment-tokens"

// TestSessionMutationRejectedWithoutCSRFToken is the SEC-007 acceptance: a
// cross-site-style forged POST that rides the session cookie but carries no
// X-CSRF-Token is rejected with 403. This is the forged-request case the
// double-submit token defends against.
func TestSessionMutationRejectedWithoutCSRFToken(t *testing.T) {
	h, tok := sessionCookieFor(t)
	req := httptest.NewRequest(http.MethodPost, mutatingPath, nil)
	req.AddCookie(&http.Cookie{Name: "__Host-trstctl_session", Value: tok})
	req.Header.Set("Idempotency-Key", "k-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("session POST without CSRF token = %d, want 403 (SEC-007)", rec.Code)
	}
}

// TestSessionMutationRejectedWithMismatchedCSRFToken: a header that does not match
// the cookie is also rejected (an attacker who guesses the header name but not the
// value still fails).
func TestSessionMutationRejectedWithMismatchedCSRFToken(t *testing.T) {
	h, tok := sessionCookieFor(t)
	req := httptest.NewRequest(http.MethodPost, mutatingPath, nil)
	req.AddCookie(&http.Cookie{Name: "__Host-trstctl_session", Value: tok})
	req.AddCookie(&http.Cookie{Name: "trstctl_csrf", Value: "the-real-token"})
	req.Header.Set("X-CSRF-Token", "a-different-token")
	req.Header.Set("Idempotency-Key", "k-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("session POST with mismatched CSRF token = %d, want 403 (SEC-007)", rec.Code)
	}
}

// TestSessionMutationPassesCSRFWithMatchingToken: a matching double-submit token
// (cookie == header) clears the CSRF gate — the request is NOT rejected for CSRF
// (it proceeds past guard; with no enroller wired the handler returns 503, which is
// explicitly not 403).
func TestSessionMutationPassesCSRFWithMatchingToken(t *testing.T) {
	h, tok := sessionCookieFor(t)
	req := httptest.NewRequest(http.MethodPost, mutatingPath, nil)
	req.AddCookie(&http.Cookie{Name: "__Host-trstctl_session", Value: tok})
	req.AddCookie(&http.Cookie{Name: "trstctl_csrf", Value: "matching-token"})
	req.Header.Set("X-CSRF-Token", "matching-token")
	req.Header.Set("Idempotency-Key", "k-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("session POST with a matching CSRF token was rejected (403); a valid double-submit must pass the CSRF gate (SEC-007)")
	}
}

// TestBearerMutationExemptFromCSRF: the bearer-token API path is CSRF-immune (a
// browser does not attach the Authorization header cross-site), so a bearer POST
// must not be rejected for a missing CSRF token. Here the bearer is bogus so authz
// returns 401 — but never 403-for-CSRF — proving the CSRF gate did not fire on the
// bearer path.
func TestBearerMutationExemptFromCSRF(t *testing.T) {
	h, _ := authAPI(t)
	req := httptest.NewRequest(http.MethodPost, mutatingPath, nil)
	req.Header.Set("Authorization", "Bearer trstctl_pat_bogus")
	req.Header.Set("Idempotency-Key", "k-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("bearer POST was rejected for CSRF (403); the bearer path is CSRF-immune and must be exempt (SEC-007)")
	}
}

// TestCallbackIssuesCSRFCookie: a successful login issues the double-submit CSRF
// cookie (non-HttpOnly so the SPA can echo it) alongside the session cookie.
func TestCallbackIssuesCSRFCookie(t *testing.T) {
	h, _ := authAPI(t)
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	req := callbackFromLogin(t, login.Result().Cookies(), "good-code")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var csrf *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "trstctl_csrf" {
			csrf = c
		}
	}
	if csrf == nil || csrf.Value == "" {
		t.Fatal("callback did not issue a CSRF cookie (SEC-007)")
	}
	if csrf.HttpOnly {
		t.Error("CSRF cookie must NOT be HttpOnly (the SPA reads it to echo in the header)")
	}
	if csrf.SameSite != http.SameSiteStrictMode {
		t.Errorf("CSRF cookie SameSite = %v, want Strict", csrf.SameSite)
	}
}
