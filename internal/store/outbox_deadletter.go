// SPDX-License-Identifier: BUSL-1.1

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
// tenant/destination. The caller is a system metric, but the data read remains
// explicitly tenant-scoped: enumerate the tenant registry, then run one
// tenant-predicated aggregation per tenant. This keeps AN-1 true even for fleet
// health and prevents a future join from accidentally blending tenant rows.
func (s *Store) OutboxDeadLetterDepth(ctx context.Context) ([]OutboxDeadLetter, error) {
	tenants, err := s.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list tenants for outbox dead-letter depth: %w", err)
	}
	var out []OutboxDeadLetter
	for _, tenant := range tenants {
		rows, queryErr := s.pool.Query(ctx,
			`SELECT tenant_id::text, destination, count(*)
			   FROM outbox
			  WHERE tenant_id = $1 AND status = 'failed'
			  GROUP BY tenant_id, destination
			  ORDER BY destination`, tenant.TenantID)
		if queryErr != nil {
			return nil, fmt.Errorf("store: outbox dead-letter depth for tenant %s: %w", tenant.TenantID, queryErr)
		}
		for rows.Next() {
			var d OutboxDeadLetter
			if scanErr := rows.Scan(&d.TenantID, &d.Destination, &d.Depth); scanErr != nil {
				rows.Close()
				return nil, fmt.Errorf("store: outbox dead-letter depth scan for tenant %s: %w", tenant.TenantID, scanErr)
			}
			out = append(out, d)
		}
		rowsErr := rows.Err()
		rows.Close()
		if rowsErr != nil {
			return nil, fmt.Errorf("store: outbox dead-letter depth rows for tenant %s: %w", tenant.TenantID, rowsErr)
		}
	}
	return out, nil
}
