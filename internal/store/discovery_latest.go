// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// LatestDiscoveryFingerprintAt returns the fingerprint of the most recently seen
// finding of kind at ref from one source, so a rescan that observes the same thing
// can record nothing (P7's network probe: a rescan with no changes writes no new
// events).
func (s *Store) LatestDiscoveryFingerprintAt(ctx context.Context, tenantID, sourceID, kind, ref string) (string, bool, error) {
	var fingerprint string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT fingerprint FROM discovery_findings
			  WHERE tenant_id = $1 AND source_id = $2::uuid AND kind = $3 AND ref = $4
			  ORDER BY last_seen_at DESC, id DESC
			  LIMIT 1`, tenantID, sourceID, kind, ref).Scan(&fingerprint)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return fingerprint, true, nil
}
