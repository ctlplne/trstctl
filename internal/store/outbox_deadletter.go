// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"
)

// OutboxDeadLetter is one tenant/destination bucket of permanently failed
// (dead-lettered) outbox rows awaiting an operator sweep or replay
// (OPS-DLQ-001).
type OutboxDeadLetter struct {
	TenantID    string
	Destination string
	Depth       int64
}

// OutboxDeadLetterDepth counts dead-lettered outbox rows per
// tenant/destination. Like the dispatch worker it is a deliberate SYSTEM
// operation over the RLS-bypassing pool (see SystemPool): the depth gauge and
// its alert are operator-facing fleet health, not tenant data access, and the
// result carries only counts plus the tenant id needed to label them.
func (s *Store) OutboxDeadLetterDepth(ctx context.Context) ([]OutboxDeadLetter, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT tenant_id::text, destination, count(*)
		   FROM outbox
		  WHERE status = 'failed'
		  GROUP BY tenant_id, destination
		  ORDER BY tenant_id, destination`)
	if err != nil {
		return nil, fmt.Errorf("store: outbox dead-letter depth: %w", err)
	}
	defer rows.Close()
	var out []OutboxDeadLetter
	for rows.Next() {
		var d OutboxDeadLetter
		if err := rows.Scan(&d.TenantID, &d.Destination, &d.Depth); err != nil {
			return nil, fmt.Errorf("store: outbox dead-letter depth scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: outbox dead-letter depth rows: %w", err)
	}
	return out, nil
}
