// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// RearmOutboxCommandTx re-arms one finished outbox command — delivered with a
// failed result, or failed terminally — named by destination and idempotency
// key, in the caller's tenant transaction (P3: a planned switch retrying a
// member's failed job). The row keeps its attempt counts, so the claim that
// follows is the same job's next attempt and its history stays visible. A
// row still pending is left alone; it reports whether a row changed.
func (s *Store) RearmOutboxCommandTx(ctx context.Context, tx pgx.Tx, tenantID, destination, idempotencyKey string) (bool, error) {
	if tenantID == "" || destination == "" || idempotencyKey == "" {
		return false, errors.New("store: outbox re-arm needs the tenant, destination and idempotency key")
	}
	tag, err := tx.Exec(ctx, `UPDATE outbox
	    SET status = 'pending', next_attempt_at = now(), delivered_at = NULL, worker_id = NULL, lease_until = NULL,
	        claimed_by_agent_id = NULL, claim_expires_at = NULL, claim_completed_at = NULL
	  WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3 AND status IN ('delivered', 'failed')`,
		tenantID, destination, idempotencyKey)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
