// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// OutboxAttempt is the operator-visible state of one exact external command.
// A delivered row says the dispatcher finished its call; it does not prove
// relying-party enforcement or a fresh signed CRL/OCSP publication.
type OutboxAttempt struct {
	ID          int64      `json:"id"`
	Destination string     `json:"destination"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	LastError   string     `json:"last_error,omitempty"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

// GetOutboxAttemptByKey returns one tenant-scoped, destination-bound command.
// Duplicate rows are an integrity failure: choosing the newest would hide an
// ambiguous external effect from an incident commander.
func (s *Store) GetOutboxAttemptByKey(ctx context.Context, tenantID, destination, key string) (OutboxAttempt, error) {
	var out OutboxAttempt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,destination,status,attempts,COALESCE(last_error,''),delivered_at
			FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3
			ORDER BY id LIMIT 2`, tenantID, destination, key)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return pgx.ErrNoRows
		}
		if err := rows.Scan(&out.ID, &out.Destination, &out.Status, &out.Attempts,
			&out.LastError, &out.DeliveredAt); err != nil {
			return err
		}
		if rows.Next() {
			return fmt.Errorf("store: duplicate exact outbox commands for tenant/destination/key")
		}
		return rows.Err()
	})
	return out, err
}
