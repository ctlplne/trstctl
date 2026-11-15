// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestPAMAccountHealthKeepsEveryCheckWithinItsHistoryA274L1L1: each
// credential health check is kept, not only the latest, so a sign-in
// collection can explain every check's sign-in; a check older than the
// history bound before an account's newest is dropped, another account's
// checks are its own, and another tenant reads none.
func TestPAMAccountHealthKeepsEveryCheckWithinItsHistoryA274L1L1(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	tenantID, other := tenantA, tenantB
	orders, billing := "a274l1l1-orders", "a274l1l1-billing"
	now := time.Now().UTC().Truncate(time.Second)
	record := func(tenant, target string, at time.Time) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyPAMAccountHealthCheckedTx(ctx, tx, tenant, store.PAMAccountHealth{
				TargetType: "postgres", TargetID: target, ProviderID: "pam-a274l1l1",
				Status: "healthy", Attempts: 1, CheckedAt: at,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	old := now.Add(-store.PAMAccountHealthCheckHistory - time.Hour)
	for _, at := range []time.Time{old, now.Add(-72 * time.Hour), now.Add(-10 * time.Minute), now.Add(-time.Minute)} {
		record(tenantID, orders, at)
	}
	record(tenantID, orders, now.Add(-10*time.Minute)) // a replayed check is one
	record(tenantID, billing, now.Add(-5*time.Minute))
	record(other, orders, now.Add(-2*time.Minute))

	got, err := s.ListPAMAccountHealthChecks(ctx, tenantID, old.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	ordersChecks := got[[2]string{"postgres", orders}]
	want := []time.Time{now.Add(-72 * time.Hour), now.Add(-10 * time.Minute), now.Add(-time.Minute)}
	if len(ordersChecks) != len(want) {
		t.Fatalf("orders' checks = %v, want %v (the one past the history bound dropped)", ordersChecks, want)
	}
	for i := range want {
		if !ordersChecks[i].Equal(want[i]) {
			t.Fatalf("orders' checks = %v, want %v", ordersChecks, want)
		}
	}
	if b := got[[2]string{"postgres", billing}]; len(b) != 1 {
		t.Fatalf("billing's checks = %v, want its one", b)
	}
	// The other tenant's check of an account with the same name is its own.
	theirs, err := s.ListPAMAccountHealthChecks(ctx, other, old.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if o := theirs[[2]string{"postgres", orders}]; len(o) != 1 || !o[0].Equal(now.Add(-2*time.Minute)) {
		t.Fatalf("the other tenant's checks of orders = %v, want only its own", o)
	}
	// The span bounds the read.
	recent, err := s.ListPAMAccountHealthChecks(ctx, tenantID, now.Add(-15*time.Minute), now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if r := recent[[2]string{"postgres", orders}]; len(r) != 1 || !r[0].Equal(now.Add(-10*time.Minute)) {
		t.Fatalf("orders' checks in the last quarter hour to two minutes ago = %v", r)
	}
	health, err := s.ListPAMAccountHealth(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if h := health[[2]string{"postgres", orders}]; !h.CheckedAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("orders' latest check = %s, want a minute ago", h.CheckedAt)
	}
}
