// SPDX-License-Identifier: BUSL-1.1

package authz_test

import (
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

// TestSecretsSessionSelfAdmitsAnyPrincipalOfItsTenantA238L7 is A238-L7's route
// predicate: every principal of the tenant may call the route that ends the
// machine session presenting the request, whatever its scopes (a read-only
// session, one with no secrets scope at all, one with no grant); another
// tenant's principal may not. It is computed: no role can grant it.
func TestSecretsSessionSelfAdmitsAnyPrincipalOfItsTenantA238L7(t *testing.T) {
	target := authz.Scope{TenantID: "tenant-a"}
	grant := func(perms ...authz.Permission) []authz.Grant {
		return []authz.Grant{{Role: authz.Role{Name: "api-token", Permissions: perms}, Scope: authz.Scope{TenantID: "tenant-a"}}}
	}
	for _, tc := range []struct {
		name      string
		principal authz.Principal
		want      bool
	}{
		{name: "a read-only session", principal: authz.Principal{TenantID: "tenant-a", Grants: grant(authz.SecretsRead)}, want: true},
		{name: "a session with no secrets scope", principal: authz.Principal{TenantID: "tenant-a", Grants: grant(authz.CertsRead)}, want: true},
		{name: "a principal with no grant", principal: authz.Principal{TenantID: "tenant-a"}, want: true},
		{name: "another tenant's session", principal: authz.Principal{TenantID: "tenant-b", Grants: grant(authz.SecretsRead)}, want: false},
	} {
		if got := tc.principal.Can(authz.SecretsSessionSelf, target); got != tc.want {
			t.Errorf("%s: Can(secrets:session.self) = %v, want %v", tc.name, got, tc.want)
		}
	}
	if !authz.IsComputed(authz.SecretsSessionSelf) {
		t.Fatal("secrets:session.self must be a computed predicate, never grantable")
	}
}
