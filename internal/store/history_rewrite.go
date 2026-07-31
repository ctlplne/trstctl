// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/events"
)

// HistoryRewriteOperationAdvisoryLockKey elects exactly one history rewriter
// across every control-plane replica connected to this PostgreSQL deployment.
// The value spells ASCII "ctlhro". It is deliberately different from the
// migration, projection, leader, CA-provision, backup, and history-barrier keys:
// those jobs protect different resources and must not accidentally block one
// another.
const HistoryRewriteOperationAdvisoryLockKey int64 = 0x63746C68726F // "ctlhro"

// HistoryRewriteBarrierAdvisoryLockKey is the deployment-wide reader/writer
// barrier for event-history generations. Replay and backup views take its shared
// side. The short freeze/activation cutover takes its exclusive side. The value
// spells ASCII "ctlhrb".
const HistoryRewriteBarrierAdvisoryLockKey int64 = 0x63746C687262 // "ctlhrb"

const historyRewriteLockPollInterval = 25 * time.Millisecond

// PostgresHistoryRewriteCoordinator implements events.HistoryRewriteCoordinator
// with PostgreSQL session advisory locks. Each lock owns one dedicated pooled
// connection for the full callback. That makes the grant deployment-wide and
// keeps a long replay/read callback independent from SQL transaction and
// statement timeouts.
type PostgresHistoryRewriteCoordinator struct {
	store *Store
}

type historyReadGrantContextKey struct{}

type historyReadLease struct {
	coordinator *PostgresHistoryRewriteCoordinator
	mu          sync.Mutex
	condition   *sync.Cond
	active      bool
	users       int
}

type historyReadGrant struct {
	lease *historyReadLease
	depth uint
}

var _ events.HistoryRewriteCoordinator = (*PostgresHistoryRewriteCoordinator)(nil)

func newHistoryReadLease(c *PostgresHistoryRewriteCoordinator) *historyReadLease {
	lease := &historyReadLease{coordinator: c, active: true}
	lease.condition = sync.NewCond(&lease.mu)
	return lease
}

func (l *historyReadLease) acquire() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.active {
		return false
	}
	l.users++
	return true
}

func (l *historyReadLease) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.users--
	if l.users == 0 {
		l.condition.Broadcast()
	}
}

func (l *historyReadLease) revokeAndWait() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active = false
	for l.users > 0 {
		l.condition.Wait()
	}
}

// NewHistoryRewriteCoordinator returns the production cross-replica coordinator
// for event-history rewrites. The returned value is safe to share between
// goroutines; PostgreSQL, rather than process memory, owns the locks.
func NewHistoryRewriteCoordinator(s *Store) *PostgresHistoryRewriteCoordinator {
	return &PostgresHistoryRewriteCoordinator{store: s}
}

// WithRewriteOperation elects one rewriter for the entire PostgreSQL deployment.
// It does not exclude readers; staging a replacement generation is safe while
// the old generation remains authoritative.
func (c *PostgresHistoryRewriteCoordinator) WithRewriteOperation(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	if c == nil || c.store == nil || c.store.historyRewriteOperationGate == nil {
		return c.withLock(ctx, HistoryRewriteOperationAdvisoryLockKey, false, "history rewrite operation", fn)
	}
	// Queue before acquiring a pooled PostgreSQL session. The database advisory
	// lock still elects across replicas, while this local gate prevents one
	// process from filling its entire pool with waiters and starving the elected
	// callback when it needs a second session for cutover/projection.
	select {
	case c.store.historyRewriteOperationGate <- struct{}{}:
		defer func() { <-c.store.historyRewriteOperationGate }()
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	return c.withLock(ctx, HistoryRewriteOperationAdvisoryLockKey, false, "history rewrite operation", fn)
}

// WithCutover excludes every WithRead view while the source is frozen, the
// replacement generation is activated, and the old generation becomes
// non-authoritative.
func (c *PostgresHistoryRewriteCoordinator) WithCutover(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	return c.withLock(ctx, HistoryRewriteBarrierAdvisoryLockKey, false, "history rewrite cutover", fn)
}

// WithRead holds the shared history-generation barrier for the complete read
// view. Multiple replays/backups may run together, but a cutover cannot change
// the authoritative generation underneath any of them.
func (c *PostgresHistoryRewriteCoordinator) WithRead(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	if fn == nil {
		return errors.New("store: history read view callback is nil")
	}
	grant, nested := ctx.Value(historyReadGrantContextKey{}).(historyReadGrant)
	if nested &&
		grant.lease != nil &&
		grant.lease.coordinator == c &&
		grant.lease.acquire() {
		defer grant.lease.release()
		// Replay and full-backup helpers can layer read-view APIs. The outer
		// callback already owns this exact coordinator's shared session grant, so
		// acquiring a second pooled connection could deadlock a one-connection
		// pool. The grant carries a private, coordinator-bound, revocable lease:
		// a context that escapes its outer callback becomes inert as soon as the
		// real PostgreSQL grant is released. Only WithRead recognizes this token;
		// cutover and operation locks always take their real PostgreSQL grants.
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		nestedCtx := context.WithValue(ctx, historyReadGrantContextKey{}, historyReadGrant{
			lease: grant.lease,
			depth: grant.depth + 1,
		})
		return fn(nestedCtx)
	}
	return c.withLock(
		ctx,
		HistoryRewriteBarrierAdvisoryLockKey,
		true,
		"history read view",
		func(lockedCtx context.Context) error {
			lease := newHistoryReadLease(c)
			defer lease.revokeAndWait()
			readCtx := context.WithValue(lockedCtx, historyReadGrantContextKey{}, historyReadGrant{
				lease: lease,
				depth: 1,
			})
			return fn(readCtx)
		},
	)
}

func (c *PostgresHistoryRewriteCoordinator) withLock(
	ctx context.Context,
	key int64,
	shared bool,
	label string,
	fn func(context.Context) error,
) (retErr error) {
	if c == nil || c.store == nil || c.store.pool == nil {
		return fmt.Errorf("store: %s coordinator is not configured", label)
	}
	if fn == nil {
		return fmt.Errorf("store: %s callback is nil", label)
	}

	conn, err := c.store.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire %s connection: %w", label, err)
	}
	locked := false
	defer func() {
		if !locked {
			conn.Release()
			return
		}
		if err := releaseHistoryRewriteLock(conn, key, shared); err != nil {
			// Returning a session to the pool with a live advisory lock would make
			// a future, unrelated borrower inherit the grant. Destroy the session
			// instead; PostgreSQL releases every session lock when it closes.
			raw := conn.Hijack()
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			closeErr := raw.Close(closeCtx)
			cancel()
			unlockErr := err
			if closeErr != nil {
				unlockErr = errors.Join(unlockErr, fmt.Errorf("close poisoned history-lock session: %w", closeErr))
			}
			if retErr == nil {
				retErr = fmt.Errorf("store: release %s: %w", label, unlockErr)
			} else {
				retErr = errors.Join(retErr, fmt.Errorf("store: release %s: %w", label, unlockErr))
			}
			return
		}
		conn.Release()
	}()

	if err := acquireHistoryRewriteLock(ctx, conn, key, shared); err != nil {
		return fmt.Errorf("store: acquire %s: %w", label, err)
	}
	locked = true
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	return fn(ctx)
}

func acquireHistoryRewriteLock(
	ctx context.Context,
	conn *pgxpool.Conn,
	key int64,
	shared bool,
) error {
	query := "SELECT pg_try_advisory_lock($1)"
	if shared {
		query = "SELECT pg_try_advisory_lock_shared($1)"
	}

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-timer.C:
		}

		var acquired bool
		if err := conn.QueryRow(ctx, query, key).Scan(&acquired); err != nil {
			return err
		}
		if acquired {
			return nil
		}
		timer.Reset(historyRewriteLockPollInterval)
	}
}

func releaseHistoryRewriteLock(conn *pgxpool.Conn, key int64, shared bool) error {
	query := "SELECT pg_advisory_unlock($1)"
	if shared {
		query = "SELECT pg_advisory_unlock_shared($1)"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var released bool
	if err := conn.QueryRow(ctx, query, key).Scan(&released); err != nil {
		return err
	}
	if !released {
		return errors.New("PostgreSQL session did not own the expected advisory lock")
	}
	return nil
}

// PrepareTenantDataCutover is the production snapshot/backup wall passed to
// events.WithTenantDataCutoverPreparation. The event layer calls it only while
// holding the exclusive history barrier. This method then takes the independent
// backup write fence, removes every reconstructible read-model snapshot, proves
// the table is empty, and invokes activation exactly once before releasing that
// fence.
//
// The report is part of the events contract and intentionally unused here:
// snapshot invalidation is deployment-wide because every snapshot was built from
// the one global event-history generation.
func (s *Store) PrepareTenantDataCutover(
	ctx context.Context,
	_ events.TenantDataRewriteReport,
	proceed func(context.Context) error,
) error {
	if s == nil || s.pool == nil {
		return errors.New("store: tenant-data cutover store is not configured")
	}
	if proceed == nil {
		return errors.New("store: tenant-data cutover proceed callback is nil")
	}
	return s.WithBackupWriteFence(ctx, func(fenceCtx context.Context) error {
		if err := s.DeleteAllSnapshots(fenceCtx); err != nil {
			return fmt.Errorf("store: invalidate snapshots before tenant-data cutover: %w", err)
		}
		remaining, err := s.SnapshotCount(fenceCtx)
		if err != nil {
			return fmt.Errorf("store: verify snapshot invalidation before tenant-data cutover: %w", err)
		}
		if remaining != 0 {
			return fmt.Errorf("store: tenant-data cutover refused: %d read-model snapshots remain", remaining)
		}
		if err := proceed(fenceCtx); err != nil {
			return fmt.Errorf("store: activate tenant-data history generation: %w", err)
		}
		return nil
	})
}
