// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// TestStatementTimeoutBoundsSlowQuery is the OPS-TIMEOUTS-001 acceptance for
// the server-side statement deadline: a runaway query is canceled by
// PostgreSQL within the configured bound and surfaces as a structured "busy"
// failure a handler maps to 503 — never an unbounded hang.
func TestStatementTimeoutBoundsSlowQuery(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, testDSN, store.WithStatementTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(s.Close)

	start := time.Now()
	_, err = s.SystemPool().Exec(ctx, "SELECT pg_sleep(5)")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("slow query was not bounded by statement_timeout")
	}
	if !store.IsBusy(err) {
		t.Fatalf("statement-timeout error is not classified busy (would 500 instead of 503): %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("slow query bounded in %v, want well under 2s for a 300ms statement_timeout", elapsed)
	}
}

// TestPoolAcquireTimeoutFailsClosedUnderSlowDependency exhausts the pool (the
// slow dependency) and proves the next transaction fails closed with
// ErrDatastoreBusy within the configured acquire window instead of queueing
// forever (OPS-TIMEOUTS-001).
func TestPoolAcquireTimeoutFailsClosedUnderSlowDependency(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, testDSN, store.WithAcquireTimeout(250*time.Millisecond))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(s.Close)

	// Hold every pooled connection like a stalled downstream would.
	pool := s.SystemPool()
	var held []interface{ Release() }
	t.Cleanup(func() {
		for _, c := range held {
			c.Release()
		}
	})
	for {
		acquireCtx, cancel := context.WithTimeout(ctx, time.Second)
		conn, err := pool.Acquire(acquireCtx)
		cancel()
		if err != nil {
			break // pool exhausted
		}
		held = append(held, conn)
	}

	start := time.Now()
	err = s.WithTenant(ctx, "00000000-0000-4000-8000-00000000beef", nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("transaction begin succeeded with an exhausted pool")
	}
	if !store.IsBusy(err) {
		t.Fatalf("pool-acquire timeout is not classified busy (would 500 instead of 503): %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("acquire failed closed in %v, want well under 2s for a 250ms window", elapsed)
	}
}
