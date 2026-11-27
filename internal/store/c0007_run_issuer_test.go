// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestC0007RunIssuerIsInRequestersApprovalLineage(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)
	_, err := s.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantA, TokenHash: privacy.SubjectRef(tenantA, "c0007-run-token"),
		Subject: "bundle-run:c0007-machine", MintedBy: "c0007-issuer",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant, requester, reviewer string
		want                        bool
	}{
		{tenantA, "bundle-run:c0007-machine", "c0007-issuer", true},
		{tenantA, "bundle-run:c0007-machine", "independent", false},
		{tenantB, "bundle-run:c0007-machine", "c0007-issuer", false},
	} {
		got, err := s.DelegatedTokenMinterMatches(ctx, tc.tenant, tc.requester, []string{tc.reviewer})
		if err != nil || got != tc.want {
			t.Errorf("tenant=%s reviewer=%s: issuer conflict=%t err=%v, want %t", tc.tenant, tc.reviewer, got, err, tc.want)
		}
	}
}
