package store

import (
	"context"
	"fmt"
)

// BackupWriteFenceAdvisoryLockKey is the fixed PostgreSQL advisory-lock key for
// full-backup consistency cuts. Tenant mutation transactions take the shared,
// transaction-scoped side of this lock before appending/projecting work; full
// backup takes the exclusive side only long enough to record the event-log head
// and pin its PostgreSQL snapshot. The value spells ASCII "ctlbkp".
const BackupWriteFenceAdvisoryLockKey int64 = 0x63746C626B70 // "ctlbkp"

// WithBackupWriteFence runs fn while holding the exclusive backup write fence.
// Callers keep fn short: capture the event-log cut and begin/pin the PostgreSQL
// repeatable-read snapshot, then release the fence before streaming backup rows.
func (s *Store) WithBackupWriteFence(ctx context.Context, fn func(context.Context) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire backup-fence connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", BackupWriteFenceAdvisoryLockKey); err != nil {
		return fmt.Errorf("store: acquire backup write fence: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", BackupWriteFenceAdvisoryLockKey)
	}()
	return fn(ctx)
}
