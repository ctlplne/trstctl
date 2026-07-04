// SPDX-License-Identifier: MPL-2.0

package server

import (
	"net/http"
)

// SecurityHeaders configures the web-hardening response headers and CORS policy
// applied to the whole served surface (SEC-003 / WIRE-005). The zero value is a
// safe default: security headers on, HSTS off (it must only be sent over TLS),
// and same-origin-only CORS (no Access-Control-Allow-Origin emitted).
type SecurityHeaders struct {
	// TLS reports whether the control plane is served over TLS. HSTS
	// (Strict-Transport-Security) is emitted only when true: sending it over
	// plaintext is both ineffective and, per RFC 6797, to be ignored, and pinning a
	// dev/plaintext host to HTTPS would be a foot-gun.
	TLS bool
	// AllowedOrigins is the explicit CORS allow-list (exact scheme+host+port). Empty
	// means same-origin only — no Access-Control-Allow-Origin is emitted, so a
	// browser blocks any cross-origin XHR. "*" is intentionally not honored for this
	// credentialed API.
	AllowedOrigins []string
}

// securityHeadersMiddleware wraps next so every served response carries the
// web-hardening headers (SEC-003): a strict Content-Security-Policy (XSS
// containment), X-Content-Type-Options: nosniff (MIME-sniffing), X-Frame-Options:
// DENY (clickjacking), Referrer-Policy: no-referrer, a conservative
// Permissions-Policy, and — over TLS only — Strict-Transport-Security. It also
// enforces a non-wildcard CORS policy: same-origin by default, or an explicit
// allow-list, reflecting only an exact-matched Origin and short-circuiting the
// preflight. It sets headers before delegating so they are present even on error
// and 304 responses.
func securityHeadersMiddleware(cfg SecurityHeaders, next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		if o != "" && o != "*" { // a credentialed API never reflects "*"
			allowed[o] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Containment: the served console is a self-contained SPA; default-deny every
		// resource class, allow same-origin scripts/styles/connections, forbid framing
		// and base-URI/ form-action hijacks, and upgrade any stray http subresource.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self'; connect-src 'self'; "+
				"object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if cfg.TLS {
			// One year, subdomains; preload is intentionally omitted (an operator opts
			// into the preload list deliberately, not by default).
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// CORS: same-origin by default. If the request carries an Origin that is on the
		// explicit allow-list, reflect exactly that origin (never "*"), advertise that
		// credentials are allowed, and answer the preflight directly. Vary: Origin so a
		// cache never serves one origin's CORS decision to another.
		if origin := r.Header.Get("Origin"); origin != "" && allowed[origin] {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-CSRF-Token, X-Project, X-Vault-Token")
			h.Set("Access-Control-Max-Age", "600")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
