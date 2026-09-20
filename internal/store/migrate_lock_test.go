// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/store"
)

// TestMigrationRunnerLockHeavyWaitsAreBounded is the OPS-MIG-LOCK-001
// acceptance: a migration statement that must WAIT for a table lock fails
// fast with SQLSTATE 55P03 (lock_not_available) under the runner's bounded
// lock_timeout instead of queueing behind live traffic indefinitely — while
// statement runtime itself stays unbounded so long CONCURRENTLY index builds
// are not killed by the pool's default statement_timeout.
func TestMigrationRunnerLockHeavyWaitsAreBounded(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// Reproduce the exact session posture the migration runner pins, on a
	// fresh connection from the same pool.
	conn, err := s.SystemPool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if err := store.ConfigureMigrationSessionForTest(ctx, conn); err != nil {
		t.Fatal(err)
	}
	var lockTimeout, stmtTimeout string
	if err := conn.QueryRow(ctx, "SHOW lock_timeout").Scan(&lockTimeout); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, "SHOW statement_timeout").Scan(&stmtTimeout); err != nil {
		t.Fatal(err)
	}
	if lockTimeout != "5s" {
		t.Fatalf("migration session lock_timeout = %q, want 5s", lockTimeout)
	}
	if stmtTimeout != "0" {
		t.Fatalf("migration session statement_timeout = %q, want 0 (unbounded work, bounded locks)", stmtTimeout)
	}

	// Live-traffic conflict: another session holds the table lock; the
	// migration-session DDL must fail fast (55P03), not hang.
	blocker, err := s.SystemPool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	if _, err := blocker.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = blocker.Exec(context.Background(), "ROLLBACK") }()
	if _, err := blocker.Exec(ctx, "LOCK TABLE owners IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = conn.Exec(ctx, "ALTER TABLE owners ADD COLUMN IF NOT EXISTS mig_lock_probe boolean")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("lock-heavy DDL succeeded while the table was exclusively locked")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("lock-heavy DDL error = %v, want SQLSTATE 55P03 lock_not_available", err)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("lock wait bounded in %v, want ~5s lock_timeout", elapsed)
	}
}
