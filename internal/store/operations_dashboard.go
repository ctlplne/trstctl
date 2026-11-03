// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// OutboxQueueStats is one tenant's outbox queue as the operations dashboard
// reads it (A246): what waits, what runs, what a worker's lease ran out on,
// what failed for good, and how long the oldest waiting command has waited.
type OutboxQueueStats struct {
	Pending    int
	Processing int
	// Stranded counts processing commands whose worker lease ran out.
	Stranded        int
	Failed          int
	OldestPendingAt *time.Time
}

// OutboxQueueStats reads the tenant's queue in one bounded aggregate.
func (s *Store) OutboxQueueStats(ctx context.Context, tenantID string) (OutboxQueueStats, error) {
	var out OutboxQueueStats
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE status = 'pending'),
			       count(*) FILTER (WHERE status = 'processing'),
			       count(*) FILTER (WHERE status = 'processing' AND lease_until IS NOT NULL AND lease_until < now()),
			       count(*) FILTER (WHERE status = 'failed'),
			       min(created_at) FILTER (WHERE status = 'pending')
			  FROM outbox
			 WHERE tenant_id = $1 AND status IN ('pending', 'processing', 'failed')`, tenantID).
			Scan(&out.Pending, &out.Processing, &out.Stranded, &out.Failed, &out.OldestPendingAt)
	})
	return out, err
}
