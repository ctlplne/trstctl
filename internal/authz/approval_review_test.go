// SPDX-License-Identifier: BUSL-1.1

package authz_test

import (
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestApprovalReviewPermissionRequiresOneRealDomainApprovalGrant(t *testing.T) {
	target := authz.Scope{TenantID: "tenant-a"}
	for _, tc := range []struct {
		name string
		perm authz.Permission
		want bool
	}{
		{name: "certificate reviewer", perm: authz.CertsIssue, want: true},
		{name: "secret reviewer", perm: authz.SecretsWrite, want: true},
		{name: "managed key reviewer", perm: authz.KeysApprove, want: true},
		{name: "read only is not a reviewer", perm: authz.CertsRead, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principal := authz.Principal{
				TenantID: target.TenantID,
				Grants: []authz.Grant{{
					Role:  authz.Role{Name: "test", Permissions: []authz.Permission{tc.perm}},
					Scope: target,
				}},
			}
			if got := principal.Can(authz.ApprovalsReview, target); got != tc.want {
				t.Fatalf("Can(approvals:review) = %v, want %v", got, tc.want)
			}
		})
	}
}
