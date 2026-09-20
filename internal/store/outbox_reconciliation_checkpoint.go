// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
)

// OutboxReconciliationCheckpoint reads the highest event-stream sequence whose
// lifecycle side-effect intent has been checked against the outbox (SPINE-003).
// It is a system, RLS-bypassing read of a single-row table because the JetStream
// sequence is global and monotonic, not tenant-scoped.
func (s *Store) OutboxReconciliationCheckpoint(ctx context.Context) (uint64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx,
		`SELECT reconciled_seq FROM outbox_reconciliation_checkpoint WHERE id = 1`).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("store: read outbox reconciliation checkpoint: %w", err)
	}
	if seq < 0 {
		seq = 0
	}
	return uint64(seq), nil
}

// AdvanceOutboxReconciliationCheckpoint moves the reconciliation watermark forward
// after the caller has checked the event's idempotent outbox effect. GREATEST keeps
// concurrent reconcilers monotonic: a slower replica cannot rewind the cursor.
func (s *Store) AdvanceOutboxReconciliationCheckpoint(ctx context.Context, seq uint64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint
		    SET reconciled_seq = GREATEST(reconciled_seq, $1), updated_at = now()
		  WHERE id = 1`, int64(seq)) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	if err != nil {
		return fmt.Errorf("store: advance outbox reconciliation checkpoint: %w", err)
	}
	return nil
}
