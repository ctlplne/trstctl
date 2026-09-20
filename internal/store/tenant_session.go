// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// PostgreSQL executes this batch in order within the caller's transaction:
// cross the backup fence, then assume the RLS role. Route resolution and tenant
// selection still happen afterward, before any caller query. This saves a
// separate request/response without changing locks, privileges or commit scope.
// An exclusive-fence owner keeps its existing single-session path instead.
func prepareTenantRoleTx(ctx context.Context, tx pgx.Tx) (err error) {
	batch := &pgx.Batch{}
	batch.Queue("SELECT pg_advisory_xact_lock_shared($1)", BackupWriteFenceAdvisoryLockKey)
	batch.Queue("SET LOCAL ROLE " + appRole)
	results := tx.SendBatch(ctx, batch)
	defer func() {
		if closeErr := results.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("store: finish tenant role setup: %w", closeErr)
		}
	}()
	if _, err := results.Exec(); err != nil {
		return fmt.Errorf("store: acquire backup write fence: %w", err)
	}
	if _, err := results.Exec(); err != nil {
		return fmt.Errorf("store: set role: %w", err)
	}
	return nil
}
