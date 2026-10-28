// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

// A207: a custom role is defined and assigned only by a caller who holds
// every permission it grants, so access:role.assign cannot mint or hand out a
// role broader than its holder.
func TestCustomRolesNeedTheCallersOwnPermissions(t *testing.T) {
	const tenantID = "20700000-0000-4000-8000-000000000002"
	scope := authz.Scope{TenantID: tenantID}
	payments := authz.Role{Name: "payments-operator", Permissions: []authz.Permission{authz.CertsRead, authz.CertsRequest}}
	a := New(nil, nil, nil, WithRoles(payments))
	as := func(perms ...authz.Permission) context.Context {
		return context.WithValue(context.Background(), principalCtxKey, authz.Principal{
			TenantID: tenantID, Subject: "carol",
			Grants: []authz.Grant{{Role: authz.Role{Name: "assigner", Permissions: perms}, Scope: scope}},
		})
	}
	narrow := as(authz.AccessWrite, authz.AccessRoleAssign, authz.CertsRead)
	err := a.authorizeRoleAssignment(narrow, tenantID, "bob", []string{"payments-operator"}, true)
	if ae, ok := err.(*apiError); !ok || ae.status != 403 || !strings.Contains(ae.detail, string(authz.CertsRequest)) {
		t.Fatalf("assigning a role broader than the caller = %#v, want 403 naming %s", err, authz.CertsRequest)
	}
	if err := requireHeldPermissions(narrow, tenantID, []string{"certs:read", "certs:request"}, "define"); err == nil ||
		!strings.Contains(err.Error(), "certs:request") {
		t.Fatalf("defining a role broader than the caller = %v", err)
	}
	wide := as(authz.AccessWrite, authz.AccessRoleAssign, authz.CertsRead, authz.CertsRequest)
	if err := a.authorizeRoleAssignment(wide, tenantID, "bob", []string{"payments-operator"}, true); err != nil {
		t.Fatalf("a caller holding every permission was refused: %v", err)
	}
	if err := requireHeldPermissions(wide, tenantID, []string{"certs:read", "certs:request"}, "define"); err != nil {
		t.Fatalf("defining within the caller's permissions = %v", err)
	}
	// Built-in roles keep their own rule: role.assign suffices for operator.
	if err := a.authorizeRoleAssignment(narrow, tenantID, "bob", []string{"operator"}, true); err != nil {
		t.Fatalf("assigning a built-in role = %v", err)
	}
	if err := a.validateRoleNameShapes([]string{"viewer", "payments-ops-reader"}); err != nil {
		t.Fatalf("baseline role names = %v", err)
	}
	if err := a.validateRoleNameShapes([]string{"Not A Role"}); err == nil {
		t.Fatal("a malformed baseline role name passed")
	}
}
