// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/tenancy"
)

// Transactions whose first statement is known up front (CI-L37 d′).
//
// pgx sends a batch as one write: each statement's Parse/Bind/Execute and one
// Sync. A tenant transaction can start that way — BEGIN, the shared backup
// write fence, the RLS role and the tenant GUC WithTenant runs, in its order,
// then the caller's statement with its parameters; nothing is written into the
// SQL.
//
//   - A read (tenantQueryRow, tenantQuery) is BEGIN READ ONLY through COMMIT in
//     one round trip. PostgreSQL refuses any write inside it, so committing
//     before the caller has looked at the rows changes nothing.
//   - A write (WithTenantFirst, WithSystemFirst) sends BEGIN, the setup and its
//     first statement in one round trip, and COMMIT only after the caller has
//     seen the result and returned nil, as WithTenant does. A caller that fails
//     or gives up before then commits nothing: the session is rolled back.
//
// When a statement fails, PostgreSQL skips the rest of the batch, and the
// session is rolled back before it returns to the pool. A caller holding the
// exclusive backup fence, and a tenant routed to a schema of its own, keep
// WithTenant's path: the fence owner's tenant work runs on the fence's own
// session, and a per-schema route statement would take a prepared-statement
// slot per schema in every pooled session.

// TxStatements is what a transaction's later statements run on: a pgx.Tx, or
// the session a pipelined transaction began on.
type TxStatements interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// tenantSetupStatements is how many statements queueTenantSetup queues.
const tenantSetupStatements = 4

// queueTenantSetup queues a tenant transaction's begin and WithTenant's setup.
func queueTenantSetup(batch *pgx.Batch, begin, tenantID string) {
	batch.Queue(begin)
	batch.Queue("SELECT pg_advisory_xact_lock_shared($1)", BackupWriteFenceAdvisoryLockKey)
	batch.Queue("SET LOCAL ROLE " + appRole)
	batch.Queue("SELECT set_config('trstctl.tenant_id', $1, true)", tenantID)
}

// pipelinesTenant reports whether a transaction for tenantID may start as one
// batch in ctx, resolving the tenant's route as WithTenant does.
func (s *Store) pipelinesTenant(ctx context.Context, tenantID string) (bool, error) {
	if underBackupWriteFence(ctx, s) {
		return false, nil
	}
	schema, err := tenancy.PostgresSchema(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("store: resolve tenant route: %w", err)
	}
	return schema == "", nil
}

// tenantQuery runs one SELECT in a read-only tenant transaction of its own and
// hands its rows to read. A failure to begin is returned as WithTenant returns
// it; the statement's own error is returned as Query's is.
func (s *Store) tenantQuery(ctx context.Context, tenantID, sql string, args []any, read func(pgx.Rows) error) error {
	consume := func(rows pgx.Rows) error {
		defer rows.Close()
		if err := read(rows); err != nil {
			return err
		}
		rows.Close()
		return rows.Err()
	}
	pipelined, err := s.pipelinesTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if !pipelined {
		return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, sql, args...)
			if err != nil {
				return err
			}
			return consume(rows)
		})
	}
	conn, err := s.acquireTenantConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	batch := &pgx.Batch{}
	queueTenantSetup(batch, "begin read only", tenantID)
	batch.Queue(sql, args...)
	batch.Queue("commit")
	results := conn.SendBatch(ctx, batch)
	err = func() error {
		for i := 0; i < tenantSetupStatements; i++ {
			if _, err := results.Exec(); err != nil {
				return fmt.Errorf("store: begin tenant transaction (fence, role, tenant): %w", err)
			}
		}
		rows, err := results.Query()
		if err != nil {
			return err
		}
		if err := consume(rows); err != nil {
			return err
		}
		_, err = results.Exec()
		return err
	}()
	if closeErr := results.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		rollbackSession(conn)
	}
	return err
}

// tenantQueryRow is tenantQuery for a statement read as QueryRow reads it.
func (s *Store) tenantQueryRow(ctx context.Context, tenantID, sql string, args []any, scan func(pgx.Row) error) error {
	return s.tenantQuery(ctx, tenantID, sql, args, func(rows pgx.Rows) error {
		return scan(firstRow{rows})
	})
}

// firstRow reads the first of rows as pgx's QueryRow does: no row is
// pgx.ErrNoRows, and Scan closes the rows.
type firstRow struct{ rows pgx.Rows }

func (r firstRow) Scan(dest ...any) error {
	if err := r.rows.Err(); err != nil {
		return err
	}
	if !r.rows.Next() {
		if err := r.rows.Err(); err != nil {
			return err
		}
		return pgx.ErrNoRows
	}
	if err := r.rows.Scan(dest...); err != nil {
		r.rows.Close()
		return err
	}
	r.rows.Close()
	return r.rows.Err()
}

// WithTenantFirst is WithTenant for a transaction whose first statement is
// known up front: BEGIN, the setup and that statement travel as one batch. fn
// sees the statement's command tag and error, and may run more statements in
// the same transaction on tx. COMMIT is sent only after fn returns nil; an
// error from fn, or a statement that failed, rolls the transaction back.
func (s *Store) WithTenantFirst(ctx context.Context, tenantID, sql string, args []any, fn func(first pgconn.CommandTag, err error, tx TxStatements) error) error {
	pipelined, err := s.pipelinesTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if !pipelined {
		return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, sql, args...)
			return fn(tag, err, tx)
		})
	}
	conn, err := s.acquireTenantConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	batch := &pgx.Batch{}
	queueTenantSetup(batch, "begin", tenantID)
	batch.Queue(sql, args...)
	tag, stmtErr, setupErr := firstResult(conn.SendBatch(ctx, batch), tenantSetupStatements)
	if setupErr != nil {
		rollbackSession(conn)
		return fmt.Errorf("store: begin tenant transaction (fence, role, tenant): %w", setupErr)
	}
	return finishFirst(ctx, conn, tag, stmtErr, fn)
}

// WithSystemFirst is WithTenantFirst on the system pool, for the system work
// SystemPool documents (no tenant role or GUC; RLS does not apply): BEGIN and
// the first statement travel as one batch, and COMMIT follows only after fn
// returns nil.
func (s *Store) WithSystemFirst(ctx context.Context, sql string, args []any, fn func(first pgconn.CommandTag, err error, tx TxStatements) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	batch := &pgx.Batch{}
	batch.Queue("begin")
	batch.Queue(sql, args...)
	tag, stmtErr, beginErr := firstResult(conn.SendBatch(ctx, batch), 1)
	if beginErr != nil {
		rollbackSession(conn)
		return beginErr
	}
	return finishFirst(ctx, conn, tag, stmtErr, fn)
}

// firstResult reads a batch's setup results, then its first statement's.
func firstResult(results pgx.BatchResults, setup int) (tag pgconn.CommandTag, stmtErr, setupErr error) {
	for i := 0; i < setup; i++ {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return tag, nil, err
		}
	}
	tag, stmtErr = results.Exec()
	if closeErr := results.Close(); stmtErr == nil {
		stmtErr = closeErr
	}
	return tag, stmtErr, nil
}

// finishFirst hands the first statement's result to fn, then commits as
// pgx's Tx.Commit does, or rolls back.
func finishFirst(ctx context.Context, conn *pgxpool.Conn, tag pgconn.CommandTag, stmtErr error, fn func(pgconn.CommandTag, error, TxStatements) error) error {
	if err := fn(tag, stmtErr, conn); err != nil {
		rollbackSession(conn)
		return err
	}
	committed, err := conn.Exec(ctx, "commit")
	if err != nil {
		if conn.Conn().PgConn().TxStatus() != 'I' {
			_ = conn.Conn().Close(ctx)
		}
		return err
	}
	if committed.String() == "ROLLBACK" {
		return pgx.ErrTxCommitRollback
	}
	return nil
}

// acquireTenantConn takes a pooled session inside the store's acquire window,
// as beginTenantTx does.
func (s *Store) acquireTenantConn(ctx context.Context) (*pgxpool.Conn, error) {
	pool := s.poolFor(ctx)
	acquireCtx := ctx
	if s.acquireTimeout > 0 {
		bounded, cancel := context.WithTimeoutCause(ctx, s.acquireTimeout, ErrDatastoreBusy)
		defer cancel()
		acquireCtx = bounded
	}
	conn, err := pool.Acquire(acquireCtx)
	if err != nil {
		if cause := context.Cause(acquireCtx); errors.Is(cause, ErrDatastoreBusy) && ctx.Err() == nil {
			return nil, fmt.Errorf("%w (acquire window %v)", ErrDatastoreBusy, s.acquireTimeout)
		}
		return nil, err
	}
	return conn, nil
}

// rollbackSession ends whatever transaction a failed batch or caller left
// open, on a context of its own so a canceled request still reaches
// PostgreSQL, as WithTenant's deferred rollback does. A session that cannot be
// rolled back is closed, which rolls it back, and the pool discards it on
// release.
func rollbackSession(conn *pgxpool.Conn) {
	if conn.Conn().IsClosed() || conn.Conn().PgConn().TxStatus() == 'I' {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, "rollback"); err != nil {
		_ = conn.Conn().Close(ctx)
	}
}
