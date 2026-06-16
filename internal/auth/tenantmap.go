package auth

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNoTenant is returned by a TenantMapper when an authenticated user cannot be
// resolved to a tenant. The served login treats it as a hard, fail-closed
// rejection (a no-tenant login is denied, not silently dropped into a default) —
// this is the TENANT-004 / RED-004 invariant: a browser session is never minted
// without a real tenant.
var ErrNoTenant = errors.New("auth: no tenant for the authenticated user")

// TenantMapping binds an OIDC user (by subject, by tenant-claim value, or by an
// IdP group) to a tenant and the RBAC roles the session receives. It is the
// table-based half of per-user → tenant mapping (TENANT-004): an operator lists
// which principals land in which tenant with which roles, replacing the single
// DefaultTenant collapse.
type TenantMapping struct {
	// Subject matches the id_token `sub`. Exactly one of Subject/Claim/Group should
	// be set per mapping; Subject is the most specific.
	Subject string
	// Claim matches the value of the verifier's configured tenant claim
	// (Claims.Tenant) — e.g. an org/tenant id the IdP stamps on the token.
	Claim string
	// Group matches one of the user's IdP groups (Claims.Groups).
	Group string
	// TenantID is the tenant the matched user is scoped to (required; RLS confines
	// the session to it, AN-1).
	TenantID string
	// Roles are the RBAC role names the session receives. Empty falls back to the
	// mapper's default roles.
	Roles []string
}

// TenantMapper resolves a verified OIDC user (its Claims) to the tenant its
// session is scoped to and the RBAC roles it holds. It is the per-user → tenant
// mapping that closes TENANT-004: instead of every browser user collapsing to one
// DefaultTenant, each authenticated subject/claim/group is mapped to its real
// tenant, and a user that maps to no tenant is rejected (fail closed). The mapper
// is config-driven and pure (no I/O), so it is deterministic and unit-testable.
//
// Resolution order, first match wins:
//  1. an explicit Subject mapping (most specific);
//  2. a tenant-claim value carried on the token (Claims.Tenant), either matched
//     against a Claim mapping or — when ClaimIsTenant is set — used directly as the
//     tenant id;
//  3. an IdP group mapping (Claims.Groups × Group mappings);
//  4. the configured DefaultTenant (only when AllowDefault is true).
//
// If none matches, ResolveTenant returns ErrNoTenant.
type TenantMapper struct {
	// Mappings is the ordered table of subject/claim/group → tenant bindings.
	Mappings []TenantMapping
	// ClaimIsTenant, when true, treats a non-empty Claims.Tenant value as the tenant
	// id directly (the IdP stamps the trstctl tenant id into the token). This is the
	// "configurable claim" mapping mode. A Claim mapping in Mappings still takes
	// precedence (it can remap or restrict claim values).
	ClaimIsTenant bool
	// DefaultTenant is the fallback tenant for a user that matches no mapping, used
	// ONLY when AllowDefault is true. It preserves the legacy single-tenant behavior
	// for a deployment that has not configured mappings yet — but it is opt-in, so a
	// multi-tenant deployment that forgets a mapping fails closed rather than leaking
	// a user into the default tenant.
	DefaultTenant string
	// DefaultRoles are the RBAC roles assigned when a matched mapping (or the default
	// fallback) does not name its own roles.
	DefaultRoles []string
	// AllowDefault permits the DefaultTenant fallback. When false (the multi-tenant
	// posture) an unmapped user is rejected with ErrNoTenant.
	AllowDefault bool
}

// ResolveTenant maps a verified user's claims to (tenantID, roles), or returns
// ErrNoTenant when the user maps to no tenant. The returned roles are never nil
// when a tenant is resolved (they default to DefaultRoles), so a mapped user
// always has a defined — possibly empty — role set.
func (m TenantMapper) ResolveTenant(c Claims) (tenantID string, roles []string, err error) {
	// 1) Subject mapping (most specific).
	for _, mp := range m.Mappings {
		if mp.Subject != "" && mp.Subject == c.Subject {
			return m.bind(mp)
		}
	}
	// 2) Tenant-claim value: an explicit Claim mapping first, then the direct
	// claim-is-tenant mode.
	if c.Tenant != "" {
		for _, mp := range m.Mappings {
			if mp.Claim != "" && mp.Claim == c.Tenant {
				return m.bind(mp)
			}
		}
		if m.ClaimIsTenant {
			return c.Tenant, m.roles(nil), nil
		}
	}
	// 3) IdP group mapping.
	for _, g := range c.Groups {
		for _, mp := range m.Mappings {
			if mp.Group != "" && mp.Group == g {
				return m.bind(mp)
			}
		}
	}
	// 4) Configured default — opt-in only.
	if m.AllowDefault && m.DefaultTenant != "" {
		return m.DefaultTenant, m.roles(nil), nil
	}
	return "", nil, fmt.Errorf("%w (subject=%q tenant_claim=%q groups=%v)", ErrNoTenant, c.Subject, c.Tenant, c.Groups)
}

func (m TenantMapper) bind(mp TenantMapping) (string, []string, error) {
	if mp.TenantID == "" {
		return "", nil, fmt.Errorf("%w: mapping has empty tenant_id", ErrNoTenant)
	}
	return mp.TenantID, m.roles(mp.Roles), nil
}

// roles returns the given roles, or the mapper's defaults when empty, always
// non-nil (an empty, defined set rather than nil).
func (m TenantMapper) roles(rs []string) []string {
	if len(rs) > 0 {
		return rs
	}
	if len(m.DefaultRoles) > 0 {
		return append([]string(nil), m.DefaultRoles...)
	}
	return []string{}
}

// Validate reports whether the mapper is internally consistent: every mapping
// names a tenant and exactly one match key, and there is SOME way to resolve a
// tenant (a mapping, the claim-is-tenant mode, or an allowed default) — otherwise
// every login would fail closed, which is almost certainly a misconfiguration.
func (m TenantMapper) Validate() error {
	var errs []error
	for i, mp := range m.Mappings {
		keys := 0
		for _, k := range []string{mp.Subject, mp.Claim, mp.Group} {
			if strings.TrimSpace(k) != "" {
				keys++
			}
		}
		if keys != 1 {
			errs = append(errs, fmt.Errorf("tenant mapping %d must set exactly one of subject/claim/group", i))
		}
		if strings.TrimSpace(mp.TenantID) == "" {
			errs = append(errs, fmt.Errorf("tenant mapping %d has empty tenant_id", i))
		}
	}
	if len(m.Mappings) == 0 && !m.ClaimIsTenant && !(m.AllowDefault && m.DefaultTenant != "") {
		errs = append(errs, errors.New("no tenant mapping configured: set a tenant_claim, a mappings table, or an explicit default tenant — otherwise every login fails closed"))
	}
	return errors.Join(errs...)
}
