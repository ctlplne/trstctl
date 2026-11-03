// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/store"
)

// noSessionInTransaction fails when a connection of the store's pool is still
// checked out or a session of the test database is still inside a
// transaction. The pool destroys a broken connection on a goroutine of its own
// after the release, so the check waits a bounded time for both counts to
// settle; a leaked connection or an abandoned transaction never does.
func noSessionInTransaction(t *testing.T, s *store.Store) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var open int
		if err := s.SystemPool().QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid() AND state LIKE 'idle in transaction%'`).Scan(&open); err != nil {
			t.Fatal(err)
		}
		held := s.SystemPool().Stat().AcquiredConns()
		if open == 0 && held == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions are still inside a transaction and %d connections are still checked out", open, held)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// tracedStore opens a second store on the migrated test database whose every
// statement and batch the tracer records.
func tracedStore(t *testing.T) (*store.Store, *setupTracer) {
	t.Helper()
	_ = newStore(t) // migrated, isolated tables
	tracer := &setupTracer{}
	s, err := store.Open(context.Background(), testDSN, store.WithQueryTracer(tracer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, tracer
}

// ownerNamed counts the owners called name in every tenant.
func ownerNamed(t *testing.T, s *store.Store, name string) int {
	t.Helper()
	var n int
	if err := s.SystemPool().QueryRow(context.Background(), `SELECT count(*) FROM owners WHERE name = $1`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// holdBackupFence takes the exclusive backup write fence on a session of its
// own and returns its release.
func holdBackupFence(t *testing.T, s *store.Store) func() {
	t.Helper()
	ctx := context.Background()
	holder, err := s.SystemPool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", store.BackupWriteFenceAdvisoryLockKey); err != nil {
		t.Fatal(err)
	}
	return func() {
		if _, err := holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", store.BackupWriteFenceAdvisoryLockKey); err != nil {
			t.Fatal(err)
		}
		holder.Release()
	}
}

const insertOwner = `INSERT INTO owners (id, tenant_id, kind, name) VALUES (gen_random_uuid(), $1, 'team', $2)`

// CI-L37 (d′): a tenant transaction whose only statement is a read is one
// round trip — BEGIN READ ONLY, the shared backup fence, the RLS role, the
// tenant GUC, the statement and COMMIT in one batch — and the statement runs
// with the role, the tenant and the fence in force, read-only, under RLS.
func TestTenantReadIsOneRoundTripUnderTheTenantFenceAndRole(t *testing.T) {
	s, tracer := tracedStore(t)
	ctx := t.Context()
	probe := `SELECT current_user, current_setting('trstctl.tenant_id'), current_setting('transaction_read_only'),
		EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND mode = 'ShareLock' AND granted)`
	read := func() (role, tenant, readOnly string, fenced bool) {
		t.Helper()
		if err := s.TenantQueryRowForTest(ctx, tenantA, probe, nil, func(row pgx.Row) error {
			return row.Scan(&role, &tenant, &readOnly, &fenced)
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	read() // the session's first use prepares the batch's statements
	tracer.take()
	role, tenant, readOnly, fenced := read()
	if role != "trstctl_app" || tenant != tenantA || readOnly != "on" || !fenced {
		t.Fatalf("the read saw role %q, tenant %q, read-only %q, fence held %v", role, tenant, readOnly, fenced)
	}
	if sent := tracer.take(); len(sent) != 1 || sent[0] != "[batch]" {
		t.Fatalf("the read sent %q; want one batch", sent)
	}
	noSessionInTransaction(t, s)

	// RLS holds: another tenant's rows are not visible, and no row is ErrNoRows.
	if _, err := s.SystemPool().Exec(ctx, insertOwner, tenantA, "pipeline-owner"); err != nil {
		t.Fatal(err)
	}
	count := func(tenant string) (n int) {
		if err := s.TenantQueryForTest(ctx, tenant, `SELECT id::text FROM owners WHERE name = 'pipeline-owner'`, nil, func(rows pgx.Rows) error {
			for rows.Next() {
				n++
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if a, b := count(tenantA), count(tenantB); a != 1 || b != 0 {
		t.Fatalf("tenant A sees %d, tenant B sees %d of tenant A's owner; want 1 and 0", a, b)
	}
	err := s.TenantQueryRowForTest(ctx, tenantB, `SELECT name FROM owners WHERE name = 'pipeline-owner'`, nil, func(row pgx.Row) error {
		var name string
		return row.Scan(&name)
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a read of no row returned %v; want pgx.ErrNoRows", err)
	}
	noSessionInTransaction(t, s)
}

// A failed statement, a setup that cannot finish, and a write slipped into a
// read commit nothing, leave no connection checked out and no session inside a
// transaction, and the pool serves the next read.
func TestTenantReadFailuresCommitNothingAndLeaveNoTransaction(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	one := func(c context.Context) error {
		return s.TenantQueryRowForTest(c, tenantA, `SELECT 1`, nil, func(row pgx.Row) error {
			var v int
			return row.Scan(&v)
		})
	}

	// The statement fails: PostgreSQL skips the COMMIT behind it.
	err := s.TenantQueryRowForTest(ctx, tenantA, `SELECT 1/0`, nil, func(row pgx.Row) error {
		var v int
		return row.Scan(&v)
	})
	if err == nil || !strings.Contains(err.Error(), "division by zero") {
		t.Fatalf("a failing statement returned %v", err)
	}
	noSessionInTransaction(t, s)
	if err := one(ctx); err != nil {
		t.Fatalf("the next read after a failed statement: %v", err)
	}

	// The setup cannot finish: an exclusive backup fence is held, so the shared
	// fence waits until the caller's deadline.
	release := holdBackupFence(t, s)
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	err = one(short)
	cancel()
	release()
	if err == nil || !strings.Contains(err.Error(), "begin tenant transaction") {
		t.Fatalf("a read through a held exclusive fence returned %v", err)
	}
	noSessionInTransaction(t, s)
	if err := one(ctx); err != nil {
		t.Fatalf("the next read after a setup that could not finish: %v", err)
	}

	// A write inside the read's transaction is refused by PostgreSQL.
	err = s.TenantQueryForTest(ctx, tenantA, `WITH w AS (`+insertOwner+` RETURNING id) SELECT id::text FROM w`, []any{tenantA, "read-only-write"}, func(rows pgx.Rows) error {
		for rows.Next() {
		}
		return rows.Err()
	})
	if err == nil || !strings.Contains(err.Error(), "read-only transaction") {
		t.Fatalf("a write inside a tenant read returned %v; want the read-only refusal", err)
	}
	if n := ownerNamed(t, s, "read-only-write"); n != 0 {
		t.Fatalf("a write inside a tenant read left %d rows", n)
	}
	noSessionInTransaction(t, s)
}

// CI-L37 (d′): a write's BEGIN, setup and first statement are one round trip;
// COMMIT follows only once the caller has seen the result and returned nil, so
// the transaction ends exactly as WithTenant's does.
func TestWithTenantFirstCommitsOnlyAfterTheCallerReturns(t *testing.T) {
	s, tracer := tracedStore(t)
	ctx := t.Context()
	write := func(name string, fn func(pgconn.CommandTag, error, store.TxStatements) error) error {
		return s.WithTenantFirst(ctx, tenantA, insertOwner, []any{tenantA, name}, fn)
	}
	plain := func(_ pgconn.CommandTag, err error, _ store.TxStatements) error { return err }

	if err := write("warm-up", plain); err != nil { // prepares the batch's statements
		t.Fatal(err)
	}
	tracer.take()
	if err := write("first-only", plain); err != nil {
		t.Fatal(err)
	}
	if sent := tracer.take(); len(sent) != 2 || sent[0] != "[batch]" || sent[1] != "commit" {
		t.Fatalf("a one-statement write sent %q; want the batch, then commit", sent)
	}
	if n := ownerNamed(t, s, "first-only"); n != 1 {
		t.Fatalf("the committed write left %d rows; want 1", n)
	}

	// The caller continues in the same transaction: it sees its own row before
	// the commit, under the tenant's role and GUC.
	tracer.take()
	var seen int
	if err := write("continued", func(tag pgconn.CommandTag, err error, tx store.TxStatements) error {
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			t.Fatalf("first statement affected %d rows", tag.RowsAffected())
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM owners WHERE name = 'continued' AND current_user = 'trstctl_app'
			AND current_setting('trstctl.tenant_id') = $1`, tenantA).Scan(&seen)
	}); err != nil {
		t.Fatal(err)
	}
	if sent := tracer.take(); seen != 1 || len(sent) != 3 || sent[0] != "[batch]" || sent[2] != "commit" {
		t.Fatalf("the continued write saw %d rows and sent %q; want 1, then the batch, the read, commit", seen, sent)
	}

	// The caller refuses after a successful statement: nothing is committed.
	refused := errors.New("refused after the statement")
	if err := write("refused", func(_ pgconn.CommandTag, err error, _ store.TxStatements) error {
		if err != nil {
			return err
		}
		return refused
	}); !errors.Is(err, refused) {
		t.Fatalf("a refusing caller returned %v", err)
	}
	if n := ownerNamed(t, s, "refused"); n != 0 {
		t.Fatalf("a refused write left %d rows", n)
	}

	// The statement fails under RLS (another tenant's row): the caller sees the
	// error and nothing is committed, and a caller that ignores it gets
	// pgx.ErrTxCommitRollback, as WithTenant's commit of an aborted transaction
	// does.
	foreign := func(fn func(pgconn.CommandTag, error, store.TxStatements) error) error {
		return s.WithTenantFirst(ctx, tenantA, insertOwner, []any{tenantB, "foreign"}, fn)
	}
	if err := foreign(plain); err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("a write for another tenant returned %v; want the RLS refusal", err)
	}
	if err := foreign(func(pgconn.CommandTag, error, store.TxStatements) error { return nil }); !errors.Is(err, pgx.ErrTxCommitRollback) {
		t.Fatalf("committing after an ignored failure returned %v; want pgx.ErrTxCommitRollback", err)
	}
	if n := ownerNamed(t, s, "foreign"); n != 0 {
		t.Fatalf("a refused foreign write left %d rows", n)
	}
	noSessionInTransaction(t, s)
}

// A write whose setup cannot finish commits nothing, even when PostgreSQL
// grants the fence after the caller gave up: COMMIT was never sent.
func TestWithTenantFirstSetupFailureCommitsNothing(t *testing.T) {
	s := newStore(t)
	release := holdBackupFence(t, s)
	short, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	err := s.WithTenantFirst(short, tenantA, insertOwner, []any{tenantA, "fenced"}, func(_ pgconn.CommandTag, err error, _ store.TxStatements) error {
		return err
	})
	cancel()
	release()
	if err == nil || !strings.Contains(err.Error(), "begin tenant transaction") {
		t.Fatalf("a write through a held exclusive fence returned %v", err)
	}
	noSessionInTransaction(t, s)
	time.Sleep(200 * time.Millisecond) // a backend that got the fence late has had time to run what it was sent
	if n := ownerNamed(t, s, "fenced"); n != 0 {
		t.Fatalf("a write whose setup timed out left %d rows", n)
	}
}

// WithSystemFirst is the same shape on the system pool: BEGIN and the
// statement in one round trip, COMMIT only after the caller returns nil.
func TestWithSystemFirstCommitsOnlyAfterTheCallerReturns(t *testing.T) {
	s, tracer := tracedStore(t)
	ctx := t.Context()
	write := func(name string, fn func(pgconn.CommandTag, error, store.TxStatements) error) error {
		return s.WithSystemFirst(ctx, insertOwner, []any{tenantA, name}, fn)
	}
	if err := write("system-warm-up", func(_ pgconn.CommandTag, err error, _ store.TxStatements) error { return err }); err != nil {
		t.Fatal(err)
	}
	tracer.take()
	if err := write("system-write", func(tag pgconn.CommandTag, err error, _ store.TxStatements) error {
		if err == nil && tag.RowsAffected() != 1 {
			return errors.New("no row")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if sent := tracer.take(); len(sent) != 2 || sent[0] != "[batch]" || sent[1] != "commit" {
		t.Fatalf("a system write sent %q; want the batch, then commit", sent)
	}
	refused := errors.New("lease lost")
	if err := write("system-refused", func(pgconn.CommandTag, error, store.TxStatements) error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("a refusing caller returned %v", err)
	}
	if a, b := ownerNamed(t, s, "system-write"), ownerNamed(t, s, "system-refused"); a != 1 || b != 0 {
		t.Fatalf("committed %d and refused %d rows; want 1 and 0", a, b)
	}
	noSessionInTransaction(t, s)
}

// A caller inside the exclusive backup fence keeps WithTenant's path: its
// pipelined reads and writes run on the fence's own session, without taking
// another connection or waiting on the fence it holds.
func TestPipelinedTenantWorkUnderTheBackupFenceUsesItsSession(t *testing.T) {
	primary := newStore(t)
	held := reserveStoreConnections(t, primary, 15)
	defer releaseStoreConnections(held)

	fenceCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := primary.WithBackupWriteFence(fenceCtx, func(ownerCtx context.Context) error {
		for i := 0; i < 2; i++ {
			if err := primary.TenantQueryRowForTest(ownerCtx, tenantA, `SELECT 1`, nil, func(row pgx.Row) error {
				var v int
				return row.Scan(&v)
			}); err != nil {
				return err
			}
		}
		return primary.WithTenantFirst(ownerCtx, tenantA, `SELECT 1`, nil, func(_ pgconn.CommandTag, err error, _ store.TxStatements) error {
			return err
		})
	})
	if err != nil {
		t.Fatalf("pipelined tenant work under the exclusive backup fence: %v", err)
	}
}
