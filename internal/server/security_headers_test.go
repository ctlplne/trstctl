// SPDX-License-Identifier: MPL-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler is a trivial inner handler the middleware wraps.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// TestSecurityHeadersPresentOnServedResponse is the SEC-003/WIRE-005 contract: a
// served response carries the five web-hardening headers (CSP, X-Content-Type-
// Options, X-Frame-Options, Referrer-Policy, and — over TLS — HSTS) plus a
// conservative Permissions-Policy. It fails on the pre-fix tree (no middleware,
// no headers) and passes once securityHeadersMiddleware wraps the surface.
func TestSecurityHeadersPresentOnServedResponse(t *testing.T) {
	h := securityHeadersMiddleware(SecurityHeaders{TLS: true}, okHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil))
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()

	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
	for k, v := range want {
		if got := res.Header.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	// CSP must be present and must contain the framing + default-deny directives.
	csp := res.Header.Get("Content-Security-Policy")
	for _, frag := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'"} {
		if !contains(csp, frag) {
			t.Errorf("CSP %q missing directive %q", csp, frag)
		}
	}
	if res.Header.Get("Permissions-Policy") == "" {
		t.Error("Permissions-Policy header is missing")
	}
}

// TestHSTSOnlyOverTLS: HSTS is emitted only when the control plane is served over
// TLS — never over plaintext (RFC 6797), so a dev/plaintext host is not pinned to
// HTTPS.
func TestHSTSOnlyOverTLS(t *testing.T) {
	h := securityHeadersMiddleware(SecurityHeaders{TLS: false}, okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	if hsts := res.Header.Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS emitted over plaintext (%q); it must be TLS-only", hsts)
	}
	// The non-HSTS headers are still present in plaintext mode.
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff header missing in plaintext mode")
	}
}

// TestCORSSameOriginByDefault: with no allow-list, no Access-Control-Allow-Origin
// is emitted, so a browser blocks any cross-origin XHR (same-origin only).
func TestCORSSameOriginByDefault(t *testing.T) {
	h := securityHeadersMiddleware(SecurityHeaders{}, okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	if aco := res.Header.Get("Access-Control-Allow-Origin"); aco != "" {
		t.Errorf("Access-Control-Allow-Origin = %q for a cross-origin request with no allow-list; want same-origin (empty)", aco)
	}
}

// TestCORSReflectsAllowedOriginOnly: an allow-listed Origin is reflected exactly
// (never "*"), an off-list Origin gets nothing, and a preflight on an allowed
// origin is answered with 204 directly.
func TestCORSReflectsAllowedOriginOnly(t *testing.T) {
	const allowed = "https://console.example.com"
	h := securityHeadersMiddleware(SecurityHeaders{AllowedOrigins: []string{allowed}}, okHandler())

	// Allowed origin → reflected.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	req.Header.Set("Origin", allowed)
	h.ServeHTTP(rec, req)
	if got := rec.Result().Header.Get("Access-Control-Allow-Origin"); got != allowed {
		t.Errorf("allowed origin not reflected: got %q, want %q", got, allowed)
	}
	if got := rec.Result().Header.Get("Access-Control-Allow-Origin"); got == "*" {
		t.Error("CORS reflected wildcard for a credentialed API")
	}

	// Off-list origin → nothing.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	req2.Header.Set("Origin", "https://attacker.example.com")
	h.ServeHTTP(rec2, req2)
	if got := rec2.Result().Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("off-list origin was allowed: %q", got)
	}

	// Preflight on the allowed origin → 204 short-circuit.
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodOptions, "/api/v1/owners", nil)
	req3.Header.Set("Origin", allowed)
	h.ServeHTTP(rec3, req3)
	if rec3.Result().StatusCode != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rec3.Result().StatusCode)
	}
	if allow := rec3.Result().Header.Get("Access-Control-Allow-Headers"); !contains(allow, "X-CSRF-Token") {
		t.Errorf("preflight allowed headers = %q, want X-CSRF-Token for SPA session mutations (SEC-001)", allow)
	}

	// "*" must never be honored even if configured.
	hw := securityHeadersMiddleware(SecurityHeaders{AllowedOrigins: []string{"*"}}, okHandler())
	recw := httptest.NewRecorder()
	reqw := httptest.NewRequest(http.MethodGet, "/", nil)
	reqw.Header.Set("Origin", "https://anything.example.com")
	hw.ServeHTTP(recw, reqw)
	if got := recw.Result().Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("'*' allow-list reflected an origin (%q); a credentialed API must not", got)
	}
}

// contains is a tiny substring helper (avoids importing strings just for the test).
func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
