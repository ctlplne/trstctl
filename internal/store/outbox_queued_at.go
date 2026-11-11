// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// OutboxRowQueuedAt is when an outbox row was queued: the start of a wait a
// delivery bounds by the row's age (A166-L3: a load balancer's propagation of
// a cloud store's change).
func (s *Store) OutboxRowQueuedAt(ctx context.Context, tenantID string, id int64) (time.Time, error) {
	var queued time.Time
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT created_at FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(&queued)
	})
	return queued, err
}
