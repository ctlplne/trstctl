package api

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestAuthorizeRoleAssignmentRequiresDedicatedPermission(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	scope := authz.Scope{TenantID: tenantID}
	memberWriter := authz.Role{Name: "member-writer", Permissions: []authz.Permission{authz.AccessWrite}}
	roleAssigner := authz.Role{Name: "role-assigner", Permissions: []authz.Permission{authz.AccessWrite, authz.AccessRoleAssign}}
	a := New(nil, nil, nil, WithRoles(memberWriter, roleAssigner))

	writerCtx := context.WithValue(context.Background(), principalCtxKey, authz.Principal{
		TenantID: tenantID,
		Subject:  "alice",
		Grants:   []authz.Grant{{Role: memberWriter, Scope: scope}},
	})
	err := a.authorizeRoleAssignment(writerCtx, tenantID, "bob", []string{"admin"}, true)
	if err == nil {
		t.Fatal("access:write-only caller assigned admin; want access:role.assign denial")
	}
	if ae, ok := err.(*apiError); !ok || ae.status != 403 || !strings.Contains(ae.detail, string(authz.AccessRoleAssign)) {
		t.Fatalf("denial = %#v, want 403 mentioning %s", err, authz.AccessRoleAssign)
	}

	assignerCtx := context.WithValue(context.Background(), principalCtxKey, authz.Principal{
		TenantID: tenantID,
		Subject:  "carol",
		Grants:   []authz.Grant{{Role: roleAssigner, Scope: scope}},
	})
	if err := a.authorizeRoleAssignment(assignerCtx, tenantID, "bob", []string{"admin"}, true); err != nil {
		t.Fatalf("role.assign holder denied: %v", err)
	}
	if err := a.authorizeRoleAssignment(assignerCtx, tenantID, "carol", []string{"admin"}, true); err == nil {
		t.Fatal("self role assignment succeeded; want self-escalation denial")
	}
	if err := a.authorizeRoleAssignment(writerCtx, tenantID, "bob", nil, false); err != nil {
		t.Fatalf("metadata-only member update should stay under access:write: %v", err)
	}
}
