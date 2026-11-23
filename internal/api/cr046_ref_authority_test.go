// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestCR046StoredReferenceRequiresSecretReadAuthority(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	a := &API{}
	ref := "secret://open/channel/token"
	for _, tc := range []struct {
		name      string
		perms     []authz.Permission
		principal bool
		wantDeny  bool
	}{
		{name: "notifier cannot select an open secret", perms: []authz.Permission{authz.NotificationsWrite}, principal: true, wantDeny: true},
		{name: "fleet worker cannot select an open secret", perms: []authz.Permission{authz.DiscoveryWrite}, principal: true, wantDeny: true},
		{name: "secret reader may select an open secret", perms: []authz.Permission{authz.SecretsRead}, principal: true},
		{name: "missing principal fails closed", wantDeny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.principal {
				ctx = context.WithValue(ctx, principalCtxKey, authz.Principal{
					TenantID: tenant, Subject: "test-caller", Grants: []authz.Grant{{
						Role: authz.Role{Name: "test", Permissions: tc.perms}, Scope: authz.Scope{TenantID: tenant},
					}},
				})
			}
			err := a.requireSecretReferencesRead(ctx, tenant, "credential_ref", ref)
			if (err != nil) != tc.wantDeny {
				t.Fatalf("reference authorization error=%v, want deny=%v", err, tc.wantDeny)
			}
		})
	}
}
