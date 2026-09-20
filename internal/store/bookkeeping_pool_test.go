// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/store"
)

// DP2-060: the idempotency claim/record/release statements run on their own
// bookkeeping pool. With every request-pool connection held, a marked
// transaction still begins promptly; an unmarked one waits out the acquire
// window and is shed. On the starting candidate the record step competed with
// the commands it bracketed, failed under a burst and walled completed commands
// as "indeterminate" (or surfaced 500).
func TestBookkeepingPoolIsNotStarvedByTheRequestPool(t *testing.T) {
	s := newStore(t)
	held := make([]*pgxpool.Conn, 0, 64)
	defer func() {
		for _, c := range held {
			c.Release()
		}
	}()
	for i := 0; i < 64; i++ {
		acquireCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := s.SystemPool().Acquire(acquireCtx)
		cancel()
		if err != nil {
			break
		}
		held = append(held, c)
	}
	if len(held) < 4 {
		t.Fatalf("held only %d request-pool connections; the pool must be saturated for this guard", len(held))
	}
	ctx := store.WithBookkeepingPool(context.Background())
	start := time.Now()
	err := s.WithTenant(ctx, "11111111-1111-4111-8111-111111111111", func(tx pgx.Tx) error {
		var one int
		return tx.QueryRow(ctx, `SELECT 1`).Scan(&one)
	})
	if err != nil {
		t.Fatalf("bookkeeping transaction while the request pool is saturated: %v", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("bookkeeping transaction took %s; it must not wait on the request pool", took)
	}
	// The same statement without the marker is shed: it competes with request work.
	unmarkedCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = s.WithTenant(unmarkedCtx, "11111111-1111-4111-8111-111111111111", func(tx pgx.Tx) error { return nil })
	if !store.IsBusy(err) {
		t.Fatalf("unmarked transaction on a saturated request pool = %v, want the datastore-busy answer", err)
	}
}
