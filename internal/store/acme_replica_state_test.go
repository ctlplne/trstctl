// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// P15-L7: an ACME nonce is redeemed once, by any replica, while it lives,
// and only by its own tenant; a tenant holds at most its limit of live
// nonces. An order's finalize claim belongs to one holder until it lapses or
// is released, and its holder may renew it.
func TestACMEReplicaStateIsSingleUseAcrossReplicasP15L7(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantID, otherTenant = "a1507000-0000-4000-8b01-000000000000", "a1507000-0000-4000-8b02-000000000000"
	seedTenant(t, s, tenantID)
	seedTenant(t, s, otherTenant)
	later := time.Now().Add(10 * time.Minute)
	if err := s.MintACMENonce(ctx, tenantID, "p15l7-nonce", later, 2); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.RedeemACMENonce(ctx, otherTenant, "p15l7-nonce"); err != nil || ok {
		t.Fatalf("another tenant redeemed the nonce: %v %v", ok, err)
	}
	if ok, err := s.RedeemACMENonce(ctx, tenantID, "p15l7-nonce"); err != nil || !ok {
		t.Fatalf("the first redemption = %v %v", ok, err)
	}
	if ok, err := s.RedeemACMENonce(ctx, tenantID, "p15l7-nonce"); err != nil || ok {
		t.Fatalf("a second redemption = %v %v", ok, err)
	}
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO acme_nonces (tenant_id, nonce_digest, expires_at) VALUES ($1, 'p15l7-expired', now() - interval '1 minute')`, tenantID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.RedeemACMENonce(ctx, tenantID, "p15l7-expired"); err != nil || ok {
		t.Fatalf("an expired nonce was redeemed: %v %v", ok, err)
	}
	for _, n := range []string{"p15l7-a", "p15l7-b"} {
		if err := s.MintACMENonce(ctx, tenantID, n, later, 2); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MintACMENonce(ctx, tenantID, "p15l7-c", later, 2); !errors.Is(err, store.ErrACMENonceLimit) {
		t.Fatalf("a nonce past the limit = %v", err)
	}
	if err := s.MintACMENonce(ctx, otherTenant, "p15l7-c", later, 2); err != nil {
		t.Fatalf("another tenant's nonce: %v", err)
	}

	claim := func(holder string, until time.Time) bool {
		t.Helper()
		ok, err := s.ClaimACMEFinalize(ctx, tenantID, "order-p15l7", holder, until)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !claim("replica-a", later) || claim("replica-b", later) || !claim("replica-a", later.Add(time.Minute)) {
		t.Fatal("a live claim was not replica-a's alone")
	}
	if err := s.ReleaseACMEFinalize(ctx, tenantID, "order-p15l7", "replica-b"); err != nil {
		t.Fatal(err)
	}
	if claim("replica-b", later) {
		t.Fatal("another holder's release dropped replica-a's claim")
	}
	if err := s.ReleaseACMEFinalize(ctx, tenantID, "order-p15l7", "replica-a"); err != nil {
		t.Fatal(err)
	}
	if !claim("replica-b", time.Now().Add(-time.Second)) {
		t.Fatal("a released order could not be claimed")
	}
	if !claim("replica-c", later) {
		t.Fatal("a lapsed claim was not taken over")
	}
}
