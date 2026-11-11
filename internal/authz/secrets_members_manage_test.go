// SPDX-License-Identifier: BUSL-1.1

package authz_test

import (
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

// TestSecretsMembersManageAdmitsAccessOrSecretsWriteA235L1 is A235-L1's route
// predicate: access:write (full membership control) or secrets:write (a
// project admin's delegated control, decided by the handler) admit the
// membership routes; read-only grants, another tenant and a grant that is not
// one of the two do not. It is computed, never grantable.
func TestSecretsMembersManageAdmitsAccessOrSecretsWriteA235L1(t *testing.T) {
	target := authz.Scope{TenantID: "tenant-a"}
	for _, tc := range []struct {
		name   string
		perm   authz.Permission
		tenant string
		want   bool
	}{
		{name: "access writer", perm: authz.AccessWrite, tenant: "tenant-a", want: true},
		{name: "secrets writer", perm: authz.SecretsWrite, tenant: "tenant-a", want: true},
		{name: "secrets reader", perm: authz.SecretsRead, tenant: "tenant-a", want: false},
		{name: "access reader", perm: authz.AccessRead, tenant: "tenant-a", want: false},
		{name: "certificate issuer", perm: authz.CertsIssue, tenant: "tenant-a", want: false},
		{name: "access writer of another tenant", perm: authz.AccessWrite, tenant: "tenant-b", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principal := authz.Principal{
				TenantID: tc.tenant,
				Grants: []authz.Grant{{
					Role:  authz.Role{Name: "test", Permissions: []authz.Permission{tc.perm}},
					Scope: authz.Scope{TenantID: tc.tenant},
				}},
			}
			if got := principal.Can(authz.SecretsMembersManage, target); got != tc.want {
				t.Fatalf("Can(secrets:members.manage) = %v, want %v", got, tc.want)
			}
		})
	}
	if !authz.IsComputed(authz.SecretsMembersManage) || !authz.IsComputed(authz.ApprovalsReview) || authz.IsComputed(authz.SecretsWrite) {
		t.Fatal("IsComputed does not name exactly the computed predicates")
	}
	for _, p := range authz.CustomRoleVocabulary() {
		if p == authz.SecretsMembersManage {
			t.Fatal("a custom role can grant the computed secrets:members.manage")
		}
	}
	for name, role := range authz.BuiltinRoles() {
		for _, p := range role.Permissions {
			if p == authz.SecretsMembersManage {
				t.Fatalf("built-in role %s holds the computed secrets:members.manage", name)
			}
		}
	}
}
