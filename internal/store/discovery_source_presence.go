// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// DiscoveryRunRef is one run of a discovery source: which, and when it
// completed.
type DiscoveryRunRef struct {
	ID          string
	CompletedAt time.Time
}

// LatestSucceededDiscoveryRuns returns, for each source given, its newest run
// that succeeded. A source whose every report is its whole inventory (P7-L2:
// an agent's MCP client configuration) no longer has a finding that this run
// did not list: a finding seen again moves to the run that saw it.
func (s *Store) LatestSucceededDiscoveryRuns(ctx context.Context, tenantID string, sourceIDs []string) (map[string]DiscoveryRunRef, error) {
	out := make(map[string]DiscoveryRunRef, len(sourceIDs))
	if len(sourceIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ON (source_id) source_id::text, id::text, coalesce(completed_at, created_at)
			  FROM discovery_runs
			 WHERE tenant_id = $1 AND source_id = ANY($2::uuid[]) AND status = 'succeeded'
			 ORDER BY source_id, created_at DESC, id DESC`, tenantID, sourceIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sourceID string
			var run DiscoveryRunRef
			if err := rows.Scan(&sourceID, &run.ID, &run.CompletedAt); err != nil {
				return err
			}
			out[sourceID] = run
		}
		return rows.Err()
	})
	return out, err
}
