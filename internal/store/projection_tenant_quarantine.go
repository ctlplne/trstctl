// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"math"
)

// ProjectionTenantQuarantined reports whether replay found an immutable event
// whose payload cannot be safely represented in this tenant's read model.
func (s *Store) ProjectionTenantQuarantined(ctx context.Context, tenantID string) (bool, error) {
	var quarantined bool
	err := s.poolFor(ctx).QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM projection_tenant_quarantines WHERE tenant_id=$1)`, tenantID).Scan(&quarantined)
	if err != nil {
		return false, fmt.Errorf("store: read projection tenant quarantine: %w", err)
	}
	return quarantined, nil
}

// RecordProjectionTenantQuarantine keeps the first failed sequence. It writes
// only bounded, fixed diagnostic codes; the event remains the audit source.
// Replaying the same history after a crash is idempotent.
func (s *Store) RecordProjectionTenantQuarantine(ctx context.Context, tenantID string, seq uint64, reasonCode string) error {
	if tenantID == "" || seq == 0 || seq > math.MaxInt64 || (reasonCode != "nul_text" && reasonCode != "invalid_utf8") {
		return fmt.Errorf("store: invalid projection tenant quarantine coordinate")
	}
	_, err := s.poolFor(ctx).Exec(ctx,
		`INSERT INTO projection_tenant_quarantines (tenant_id, first_failed_seq, reason_code)
		 VALUES ($1,$2,$3) ON CONFLICT (tenant_id) DO NOTHING`, tenantID, int64(seq), reasonCode) // #nosec G115 -- range checked above (CWE-190)
	if err != nil {
		return fmt.Errorf("store: record projection tenant quarantine: %w", err)
	}
	return nil
}
