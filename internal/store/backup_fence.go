// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackupWriteFenceAdvisoryLockKey is the fixed PostgreSQL advisory-lock key for
// full-backup consistency cuts. Tenant mutation transactions take the shared,
// transaction-scoped side of this lock before appending/projecting work; full
// backup takes the exclusive side only long enough to record the event-log head
// and pin its PostgreSQL snapshot. The value spells ASCII "ctlbkp".
const BackupWriteFenceAdvisoryLockKey int64 = 0x63746C626B70 // "ctlbkp"

type backupWriteFenceContextKey struct{}

// pooledPostgresStateSnapshotTx keeps the one pooled connection that performed
// the session-lock -> transaction-lock handoff checked out until the export
// transaction ends. pgxpool.Pool.BeginTx normally owns that release step, but
// both the standalone shared handoff and the full-backup exclusive-to-shared
// downgrade must begin on their already locked *pgxpool.Conn so there is no
// second-slot deadlock and no cutover gap.
type pooledPostgresStateSnapshotTx struct {
	pgx.Tx
	conn *pgxpool.Conn
}

func (tx *pooledPostgresStateSnapshotTx) Commit(ctx context.Context) error {
	err := tx.Tx.Commit(ctx)
	tx.release()
	return err
}

func (tx *pooledPostgresStateSnapshotTx) Rollback(ctx context.Context) error {
	err := tx.Tx.Rollback(ctx)
	tx.release()
	return err
}

func (tx *pooledPostgresStateSnapshotTx) release() {
	if tx.conn == nil {
		return
	}
	tx.conn.Release()
	tx.conn = nil
}

// backupWriteFenceLease is unforgeable authority to reuse the exact PostgreSQL
// session that owns the exclusive backup fence. Reuse is needed for tenant reads
// performed while preparing a history cutover: asking another session for the
// shared side would wait on this session forever.
//
// active makes an escaped callback context inert. handedOff permanently revokes
// nested session reuse after the full-backup snapshot atomically downgrades the
// lock and takes ownership of the connection. use serializes the one pgx
// connection and lets revocation wait until every already-entered nested tenant
// transaction or handoff step has finished.
type backupWriteFenceLease struct {
	store     *Store
	conn      *pgxpool.Conn
	active    atomic.Bool
	handedOff atomic.Bool
	use       chan struct{}
}

func newBackupWriteFenceLease(s *Store, conn *pgxpool.Conn) *backupWriteFenceLease {
	lease := &backupWriteFenceLease{
		store: s,
		conn:  conn,
		use:   make(chan struct{}, 1),
	}
	lease.active.Store(true)
	return lease
}

func backupWriteFenceLeaseFromContext(
	ctx context.Context,
	s *Store,
) (*backupWriteFenceLease, bool) {
	lease, ok := ctx.Value(backupWriteFenceContextKey{}).(*backupWriteFenceLease)
	if !ok || lease == nil || lease.store != s || lease.conn == nil ||
		!lease.active.Load() || lease.handedOff.Load() {
		return nil, false
	}
	select {
	case lease.use <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}
	// Revocation may have raced while this caller waited for the session. Check
	// again after becoming its sole user.
	if !lease.active.Load() || lease.handedOff.Load() {
		<-lease.use
		return nil, false
	}
	return lease, true
}

func (l *backupWriteFenceLease) releaseUse() {
	<-l.use
}

func (l *backupWriteFenceLease) revokeAndWait() {
	l.active.Store(false)
	// Taking and releasing the single-user token waits for an already-authorized
	// nested transaction. No new caller can pass the active recheck above.
	l.use <- struct{}{}
	<-l.use
}

// WithBackupWriteFence runs fn while holding the exclusive backup write fence.
// Callers keep fn short: capture the event-log cut and begin/pin the PostgreSQL
// repeatable-read snapshot, then release the fence before streaming backup rows.
//
// The callback receives a scoped context that lets this exact Store reuse the
// lock-owning session for nested WithTenant work. That context is valid only
// while fn is running; saving it for later grants no authority.
func (s *Store) WithBackupWriteFence(
	ctx context.Context,
	fn func(context.Context) error,
) (retErr error) {
	if s == nil || s.pool == nil {
		return errors.New("store: backup write fence store is not configured")
	}
	if fn == nil {
		return errors.New("store: backup write fence callback is nil")
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire backup-fence connection: %w", err)
	}
	locked := false
	var lease *backupWriteFenceLease
	defer func() {
		if conn == nil {
			return
		}
		// BeginPostgresStateSnapshotTx can atomically downgrade this session's
		// exclusive grant into a transaction-scoped shared grant and transfer
		// ownership of the checked-out connection to the returned transaction.
		// In that case the exclusive lock is already gone, and Commit/Rollback
		// releases the connection after the shared transaction lock ends.
		if lease != nil && lease.handedOff.Load() {
			return
		}
		if !locked {
			conn.Release()
			return
		}
		if err := releaseBackupWriteFence(conn); err != nil {
			// A pooled session carrying an exclusive advisory lock would silently
			// freeze future tenant mutations. Destroy it so PostgreSQL releases
			// the lock with the session instead of returning it to the pool.
			raw := conn.Hijack()
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			closeErr := raw.Close(closeCtx)
			cancel()
			unlockErr := err
			if closeErr != nil {
				unlockErr = errors.Join(unlockErr, fmt.Errorf("close poisoned backup-fence session: %w", closeErr))
			}
			if retErr == nil {
				retErr = fmt.Errorf("store: release backup write fence: %w", unlockErr)
			} else {
				retErr = errors.Join(retErr, fmt.Errorf("store: release backup write fence: %w", unlockErr))
			}
			return
		}
		conn.Release()
	}()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", BackupWriteFenceAdvisoryLockKey); err != nil {
		// A cancelled/failed round trip can make it ambiguous whether PostgreSQL
		// granted the session lock before the client saw the error. Never return
		// that session to the pool: closing it makes either state safe.
		raw := conn.Hijack()
		conn = nil
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := raw.Close(closeCtx)
		cancel()
		if closeErr != nil {
			return errors.Join(
				fmt.Errorf("store: acquire backup write fence: %w", err),
				fmt.Errorf("store: close ambiguous backup-fence session: %w", closeErr),
			)
		}
		return fmt.Errorf("store: acquire backup write fence: %w", err)
	}
	locked = true
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}

	lease = newBackupWriteFenceLease(s, conn)
	fenceCtx := context.WithValue(ctx, backupWriteFenceContextKey{}, lease)
	defer func() {
		lease.revokeAndWait()
	}()
	return fn(fenceCtx)
}

func releaseBackupWriteFence(conn *pgxpool.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var released bool
	if err := conn.QueryRow(
		ctx,
		"SELECT pg_advisory_unlock($1)",
		BackupWriteFenceAdvisoryLockKey,
	).Scan(&released); err != nil {
		return err
	}
	if !released {
		return errors.New("PostgreSQL session did not own the expected backup write fence")
	}
	return nil
}

// BeginPostgresStateSnapshotTx starts the read-only repeatable-read transaction
// used by a PostgreSQL-state export without leaving a cutover race before its
// MVCC snapshot is pinned.
//
// A standalone caller uses ONE pooled session for this exact handoff:
//
//  1. take the session-scoped shared backup fence;
//  2. BEGIN the repeatable-read transaction on that same session;
//  3. take the transaction-scoped shared fence;
//  4. explicitly pin the transaction's MVCC snapshot; and
//  5. release the session-scoped guard.
//
// The transaction lock then protects the pinned snapshot until Commit/Rollback.
// The session guard is therefore never held on connection A while BEGIN waits
// for connection B, which keeps the path safe even when only one pool slot is
// available. A full-backup caller already owns the exclusive fence through the
// unforgeable callback context. It performs the same handoff on the lock-owning
// session: BEGIN, take the transaction-scoped shared side, pin MVCC, release
// the session-scoped exclusive side, then transfer that checked-out connection
// to the returned transaction. This preserves event-cut -> snapshot ordering
// while letting mutations resume during the long event/PostgreSQL streams.
func (s *Store) BeginPostgresStateSnapshotTx(ctx context.Context) (pgx.Tx, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: postgres-state snapshot store is not configured")
	}
	if lease, ok := backupWriteFenceLeaseFromContext(ctx, s); ok {
		defer lease.releaseUse()
		tx, err := lease.conn.BeginTx(ctx, pgx.TxOptions{
			IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
		})
		if err != nil {
			return nil, fmt.Errorf("store: begin postgres-state snapshot under backup fence: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"SELECT pg_advisory_xact_lock_shared($1)",
			BackupWriteFenceAdvisoryLockKey,
		); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = tx.Rollback(rollbackCtx)
			cancel()
			return nil, fmt.Errorf("store: hand off full-backup snapshot fence: %w", err)
		}
		if err := pinPostgresStateSnapshot(ctx, tx); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = tx.Rollback(rollbackCtx)
			cancel()
			return nil, err
		}
		var released bool
		if err := tx.QueryRow(ctx,
			"SELECT pg_advisory_unlock($1)",
			BackupWriteFenceAdvisoryLockKey,
		).Scan(&released); err != nil || !released {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = tx.Rollback(rollbackCtx)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("store: release full-backup exclusive snapshot fence: %w", err)
			}
			return nil, errors.New("store: full-backup session did not own its exclusive fence")
		}
		lease.handedOff.Store(true)
		return &pooledPostgresStateSnapshotTx{Tx: tx, conn: lease.conn}, nil
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquire postgres-state snapshot connection: %w", err)
	}
	closeAmbiguous := func() {
		raw := conn.Hijack()
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = raw.Close(closeCtx)
		cancel()
	}

	// This is deliberately a session lock acquired before BEGIN. A blocking
	// acquire is safe on this dedicated connection; if the round trip fails, the
	// session is destroyed because grant ownership is ambiguous.
	if _, err := conn.Exec(ctx,
		"SELECT pg_advisory_lock_shared($1)",
		BackupWriteFenceAdvisoryLockKey,
	); err != nil {
		closeAmbiguous()
		return nil, fmt.Errorf("store: acquire postgres-state snapshot session fence: %w", err)
	}

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		closeAmbiguous()
		return nil, fmt.Errorf("store: begin guarded postgres-state snapshot: %w", err)
	}
	if _, err := tx.Exec(ctx,
		"SELECT pg_advisory_xact_lock_shared($1)",
		BackupWriteFenceAdvisoryLockKey,
	); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tx.Rollback(rollbackCtx)
		cancel()
		closeAmbiguous()
		return nil, fmt.Errorf("store: hand off postgres-state snapshot fence: %w", err)
	}
	if err := pinPostgresStateSnapshot(ctx, tx); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tx.Rollback(rollbackCtx)
		cancel()
		closeAmbiguous()
		return nil, err
	}

	// The transaction-scoped grant is now held on this same session and the
	// repeatable-read snapshot is pinned. Dropping the temporary session grant
	// cannot open a cutover gap.
	var released bool
	if err := tx.QueryRow(ctx,
		"SELECT pg_advisory_unlock_shared($1)",
		BackupWriteFenceAdvisoryLockKey,
	).Scan(&released); err != nil || !released {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tx.Rollback(rollbackCtx)
		cancel()
		closeAmbiguous()
		if err != nil {
			return nil, fmt.Errorf("store: release postgres-state snapshot session fence: %w", err)
		}
		return nil, errors.New("store: postgres-state snapshot session did not own its shared fence")
	}

	return &pooledPostgresStateSnapshotTx{Tx: tx, conn: conn}, nil
}

func pinPostgresStateSnapshot(ctx context.Context, tx pgx.Tx) error {
	var snapshot string
	// pg_current_snapshot() forces PostgreSQL to assign this repeatable-read
	// transaction's MVCC snapshot while the session-level guard is still held.
	// Full backup needs that explicit pin before releasing exclusive: otherwise a
	// normal shared-fence mutation could commit after the event cut but before the
	// first table read and leak post-cut SQL into the paired artifact.
	if err := tx.QueryRow(ctx, `SELECT pg_current_snapshot()::text`).Scan(&snapshot); err != nil {
		return fmt.Errorf("store: pin postgres-state MVCC snapshot: %w", err)
	}
	if snapshot == "" {
		return errors.New("store: PostgreSQL returned an empty snapshot identifier")
	}
	return nil
}
