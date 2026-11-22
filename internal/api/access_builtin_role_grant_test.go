// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

// CR-023: built-in names are not a shortcut around the rule that an assigner
// must hold every permission the new role grants.
func TestBuiltinRoleGrantRequiresEveryGrantedPermission(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	scope := authz.Scope{TenantID: tenantID}
	a := New(nil, nil, nil)
	operator := authz.BuiltinRoles()["operator"]
	for _, tc := range []struct {
		name   string
		holder authz.Role
		grant  string
		lacks  authz.Permission
	}{
		{"provisioner grants operator", authz.Role{Name: "provisioner", Permissions: []authz.Permission{authz.AccessWrite, authz.AccessRoleAssign}}, "operator", authz.SecretsRead},
		{"operator grants auditor", operator, "auditor", authz.AuditRead},
		{"operator grants cli", operator, "cli", authz.AuditRead},
		{"operator grants mcp", operator, "mcp", authz.AuditRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := authz.Principal{TenantID: tenantID, Subject: "assigner", Grants: []authz.Grant{{Role: tc.holder, Scope: scope}}}
			if p.Can(tc.lacks, scope) {
				t.Fatalf("fixture already holds %s", tc.lacks)
			}
			ctx := context.WithValue(context.Background(), principalCtxKey, p)
			err := a.authorizeRoleAssignment(ctx, tenantID, "recipient", []string{tc.grant}, true)
			if err == nil || !strings.Contains(err.Error(), "which you do not hold") {
				t.Fatalf("granted built-in %s without holding %s: %v", tc.grant, tc.lacks, err)
			}
		})
	}
}
