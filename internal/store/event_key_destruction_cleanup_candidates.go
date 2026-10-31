// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
)

type SettledEventKeyDestructionIntent struct {
	ID             int64
	TenantID       string
	IdempotencyKey string
	Payload        []byte
}

// ListSettledEventKeyDestructionIntents reads at most 16 exact finalized intents.
// The caller must verify retained signed completion and CURRENT custody before
// removing any row. A delivered status is not evidence of key destruction.
func (s *Store) ListSettledEventKeyDestructionIntents(ctx context.Context, afterID int64) ([]SettledEventKeyDestructionIntent, error) {
	if s == nil || afterID < 0 {
		return nil, errors.New("store: invalid settled event-key page")
	}
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant system maintenance reads at most 16 exact finalized event-key intents with bounded payload bytes; each candidate needs current signed-source and custody verification before removal in its tenant-scoped RLS transaction. No API caller receives these bytes, and this read grants no key-removal authority.
		`SELECT id,tenant_id::text,idempotency_key,substring(payload FROM 1 FOR 16385)
  FROM outbox WHERE id>$1 AND destination='eventprivacy.destroy'
  AND COALESCE(NULLIF(effect_lane,''),destination)=destination
  AND required_agent_role='control_plane' AND required_agent_id IS NULL
  AND status='delivered' AND cardinality(receiver_pending_ids)=0
  ORDER BY id LIMIT 16`, afterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SettledEventKeyDestructionIntent
	for rows.Next() {
		var row SettledEventKeyDestructionIntent
		if err := rows.Scan(&row.ID, &row.TenantID, &row.IdempotencyKey, &row.Payload); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
