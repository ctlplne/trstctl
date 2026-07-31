// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BackupWriteFenceAdvisoryLockKey is the fixed PostgreSQL advisory-lock key for
// full-backup consistency cuts. Tenant mutation transactions take the shared,
// transaction-scoped side of this lock before appending/projecting work; full
// backup takes the exclusive side only long enough to record the event-log head
// and pin its PostgreSQL snapshot. The value spells ASCII "ctlbkp".
const BackupWriteFenceAdvisoryLockKey int64 = 0x63746C626B70 // "ctlbkp"

type backupWriteFenceContextKey struct{}

// backupWriteFenceLease is unforgeable authority to reuse the exact PostgreSQL
// session that owns the exclusive backup fence. Reuse is needed for tenant reads
// performed while preparing a history cutover: asking another session for the
// shared side would wait on this session forever.
//
// active makes an escaped callback context inert. use serializes the one pgx
// connection and lets revocation wait until every already-entered nested tenant
// transaction has finished before the exclusive lock is released.
type backupWriteFenceLease struct {
	store  *Store
	conn   *pgxpool.Conn
	active atomic.Bool
	use    chan struct{}
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
	if !ok || lease == nil || lease.store != s || lease.conn == nil || !lease.active.Load() {
		return nil, false
	}
	select {
	case lease.use <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}
	// Revocation may have raced while this caller waited for the session. Check
	// again after becoming its sole user.
	if !lease.active.Load() {
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
	defer func() {
		if conn == nil {
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

	lease := newBackupWriteFenceLease(s, conn)
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
