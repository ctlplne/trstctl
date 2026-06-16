package api

import (
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
)

// WithInsecureHeaderResolver installs a principal resolver that TRUSTS request
// headers (X-Tenant-ID, X-Roles, X-Subject, X-Role-Project). It authenticates
// NOTHING — anyone who can reach the API can claim any tenant and any role — so
// it must NEVER be used in production. It exists only so tests (and local dev)
// can exercise RBAC and project scoping without standing up an IdP or minting
// tokens for every case.
//
// It is wired through a resolver factory (config.principalFromReg) rather than a
// direct resolver, so the resolver function is referenced ONLY from this option.
// Because the production composition root never calls this option, the linker
// dead-code-eliminates insecureHeaderResolver from the shipped control-plane
// binary — asserted by TestProductionBinaryDoesNotLinkHeaderTrust, mirroring the
// AN-4 signer isolation guard.
func WithInsecureHeaderResolver() Option {
	return func(c *config) { c.principalFromReg = insecureHeaderResolver }
}

// insecureHeaderResolver resolves the caller's principal from request headers.
// X-Roles is a comma-separated list of role names (resolved against the given
// registry, so custom roles work); X-Role-Project is the project those roles are
// granted in ("" = tenant-wide). It is the test-only header-trust path. When no
// X-Tenant-ID header is present it defers to the real authenticated resolver, so
// a test server built with this option still accepts bearer tokens and sessions.
func insecureHeaderResolver(reg *authz.Registry, fallback func(*http.Request) (authz.Principal, error)) func(*http.Request) (authz.Principal, error) {
	return func(r *http.Request) (authz.Principal, error) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			return fallback(r)
		}
		scope := authz.Scope{TenantID: tenantID, Project: r.Header.Get("X-Role-Project")}
		var grants []authz.Grant
		for _, name := range strings.Split(r.Header.Get("X-Roles"), ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if role, ok := reg.Role(name); ok {
				grants = append(grants, authz.Grant{Role: role, Scope: scope})
			}
		}
		return authz.Principal{TenantID: tenantID, Subject: r.Header.Get("X-Subject"), Grants: grants}, nil
	}
}
