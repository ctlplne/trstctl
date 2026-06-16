package projections_test

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestMigrateSerializesViaAdvisoryLock is the R2.5 disconfirming test for the
// migration findings: Migrate gates the whole run on a PostgreSQL advisory lock,
// so two control-plane instances booting simultaneously cannot both run
// migrations at once (the replica-boot race the audit flagged). While the lock
// is held by an independent session, Migrate blocks rather than racing ahead;
// once the lock is released, it proceeds.
func TestMigrateSerializesViaAdvisoryLock(t *testing.T) {
	st := newStore(t) // shared database, already migrated
	ctx := context.Background()

	// Hold the migration advisory lock from an independent session.
	holder, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("connect holder: %v", err)
	}
	defer func() { _ = holder.Close(context.Background()) }()
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", store.MigrateAdvisoryLockKey); err != nil {
		t.Fatalf("hold migration lock: %v", err)
	}

	// Migrate must block while the lock is held.
	done := make(chan error, 1)
	go func() {
		mctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		done <- st.Migrate(mctx)
	}()

	select {
	case err := <-done:
		t.Fatalf("Migrate returned while the advisory lock was held (err=%v): it did not wait on the lock", err)
	case <-time.After(600 * time.Millisecond):
		// Still blocked on the lock — correct.
	}

	// Release the lock; Migrate should now acquire it and complete.
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", store.MigrateAdvisoryLockKey); err != nil {
		t.Fatalf("release migration lock: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migrate after lock release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Migrate did not complete after the advisory lock was released")
	}
}

// TestMigrateConcurrentInstancesApplyExactlyOnce simulates several instances
// booting against the same fresh database at once. With the advisory lock, every
// Migrate succeeds and the schema is applied exactly once — no double-apply, no
// "already exists" corruption. Without the lock, the concurrent applies collide.
func TestMigrateConcurrentInstancesApplyExactlyOnce(t *testing.T) {
	ctx := context.Background()
	freshDSN := freshMigrationDB(t)

	const instances = 6
	stores := make([]*store.Store, instances)
	for i := range stores {
		s, err := store.Open(ctx, freshDSN)
		if err != nil {
			t.Fatalf("open store %d: %v", i, err)
		}
		stores[i] = s
		t.Cleanup(s.Close)
	}

	var wg sync.WaitGroup
	errs := make([]error, instances)
	start := make(chan struct{})
	for i, s := range stores {
		wg.Add(1)
		go func(i int, s *store.Store) {
			defer wg.Done()
			<-start
			errs[i] = s.Migrate(ctx)
		}(i, s)
	}
	close(start) // release all instances at once
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Migrate %d failed (replica-boot race not prevented): %v", i, err)
		}
	}

	// Exactly-once: nothing pending afterward, and no duplicate ledger rows.
	if pending, err := stores[0].PendingMigrations(ctx); err != nil {
		t.Fatalf("PendingMigrations: %v", err)
	} else if len(pending) != 0 {
		t.Fatalf("after concurrent migrate, %d migrations still pending: %v", len(pending), pending)
	}
	var total, distinct int
	if err := stores[0].Pool().QueryRow(ctx,
		"SELECT count(*), count(distinct version) FROM schema_migrations").Scan(&total, &distinct); err != nil {
		t.Fatalf("ledger count: %v", err)
	}
	if total == 0 || total != distinct {
		t.Fatalf("schema_migrations has %d rows / %d distinct versions; want equal and non-zero (no double-apply)", total, distinct)
	}
}

// TestPendingMigrationsReportsPlan: the dry-run plan lists every migration on a
// fresh database (the pre-migration check an operator runs before backing up),
// and reports an empty plan once they are applied.
func TestPendingMigrationsReportsPlan(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, freshMigrationDB(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(s.Close)

	pending, err := s.PendingMigrations(ctx)
	if err != nil {
		t.Fatalf("PendingMigrations(fresh): %v", err)
	}
	if len(pending) == 0 {
		t.Fatal("a fresh database should report pending migrations")
	}
	if !strings.HasPrefix(pending[0], "0001") {
		t.Errorf("first pending migration = %q, want it sorted with 0001_* first", pending[0])
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	after, err := s.PendingMigrations(ctx)
	if err != nil {
		t.Fatalf("PendingMigrations(after): %v", err)
	}
	if len(after) != 0 {
		t.Errorf("after Migrate, still pending: %v", after)
	}
}

// freshMigrationDB creates an empty database on the shared test server and
// returns a DSN to it — a clean "new deployment" to migrate. The database is
// dropped when the test finishes.
func freshMigrationDB(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	name := fmt.Sprintf("trstctl_migr_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u, err := url.Parse(testDSN)
	if err != nil {
		t.Fatalf("parse testDSN: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}
