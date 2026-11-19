// SPDX-License-Identifier: BUSL-1.1

package authz_test

import (
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

// CR-101: a bundle run wraps the principal once and preserves the name.
func TestApprovalPrincipalMatchesOnlyTheBundleRunOwner(t *testing.T) {
	for _, test := range []struct {
		requester, reviewer string
		same                bool
	}{
		{"owner", "owner", true},
		{"bundle-run:owner", "owner", true},
		{"owner", "bundle-run:owner", true},
		{"bundle-run:owner", "bundle-run:other", false},
		{"bundle-run:Owner", "owner", false},
		{"bundle-run:owner ", "owner", false},
		{"bundle-run:bundle-run:owner", "owner", false},
		{"bundle-run:", "", false},
	} {
		if got := authz.SameApprovalPrincipal(test.requester, test.reviewer); got != test.same {
			t.Errorf("SameApprovalPrincipal(%q, %q) = %v, want %v", test.requester, test.reviewer, got, test.same)
		}
	}
}

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
		{name: "privileged access reviewer", perm: authz.AccessApprove, want: true},
		{name: "privileged access writer cannot review", perm: authz.AccessWrite, want: false},
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
