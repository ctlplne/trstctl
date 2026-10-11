// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"
)

func TestIncidentPredecessorCRLPublishesExactAuthorityAndFailsClosed(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const managedCA = "49300000-0000-4000-8000-000000000001"
	var platformCalls, managedCalls int
	d := &issuanceDispatcher{
		publishCRL: func(_ context.Context, gotTenant string) error {
			if gotTenant != tenant {
				t.Fatalf("platform CRL tenant = %q", gotTenant)
			}
			platformCalls++
			return nil
		},
		publishAuthorityCRL: func(_ context.Context, gotTenant, gotCA string) error {
			if gotTenant != tenant || gotCA != managedCA {
				t.Fatalf("managed CRL = %q/%q", gotTenant, gotCA)
			}
			managedCalls++
			return nil
		},
	}
	ctx := context.Background()
	if err := d.publishPredecessorCRL(ctx, tenant, managedCA); err != nil || platformCalls != 0 || managedCalls != 1 {
		t.Fatalf("managed publication err=%v platform=%d managed=%d", err, platformCalls, managedCalls)
	}
	if err := d.publishPredecessorCRL(ctx, tenant, IssuingCAID()); err != nil || platformCalls != 1 || managedCalls != 1 {
		t.Fatalf("platform publication err=%v platform=%d managed=%d", err, platformCalls, managedCalls)
	}
	d.publishAuthorityCRL = nil
	if err := d.publishPredecessorCRL(ctx, tenant, managedCA); err == nil {
		t.Fatal("missing managed CA publisher acknowledged a revocation")
	}
	d.publishAuthorityCRL = func(context.Context, string, string) error { return errors.New("signer offline") }
	if err := d.publishPredecessorCRL(ctx, tenant, managedCA); err == nil || err.Error() != "signer offline" {
		t.Fatalf("managed publication failure = %v", err)
	}
}
