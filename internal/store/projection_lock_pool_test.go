// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DP2-061: the session that holds the projection advisory lock comes from the
// lock pool, so a command waiting for the lock never occupies a request-pool
// connection. With every request-pool connection held, WithProjectionLock still
// takes the lock promptly; on the starting candidate it acquired its session
// from the request pool and a 24-way profile burst convoyed on the lock for
// ten seconds per holder (waiters parked on request-pool connections starved
// the holder's nested transactions into the acquire window).
func TestProjectionLockIsNotStarvedByTheRequestPool(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	entered := false
	err := s.WithProjectionLock(ctx, func(context.Context) error {
		entered = true
		return nil
	})
	if err != nil {
		t.Fatalf("WithProjectionLock while the request pool is saturated: %v", err)
	}
	if !entered {
		t.Fatal("callback did not run")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("taking the projection lock took %s; the lock session must not wait on the request pool", took)
	}
}
