// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApplyKeyCompromiseHostRetryTx is called only by the projector for an
// identity.key_compromise_effect_retried host event. It moves the exact retained
// containment receipt onto the fresh endpoint.contain outbox row and returns it
// to the queued state. The agent's later signed result converges on that row.
// An older event never rewinds a receipt that a newer event already advanced.
func (s *Store) ApplyKeyCompromiseHostRetryTx(ctx context.Context, tx pgx.Tx, tenantID, receiptID,
	identityID string, outboxID int64, attempt int, sequence uint64, at time.Time) error {
	if receiptID == "" || identityID == "" || outboxID <= 0 || attempt < 1 || sequence == 0 || sequence > math.MaxInt64 {
		return errors.New("store: key-compromise host retry needs the exact receipt, identity, outbox row, attempt and bounded sequence")
	}
	seq := int64(sequence) // #nosec G115 -- bounded above by the MaxInt64 check; the column is a Postgres bigint (CWE-190)
	detail := fmt.Sprintf("Retry %d queued: awaiting the exact enrolled host agent; no stop or listener verification has happened.", attempt)
	tag, err := tx.Exec(ctx, `UPDATE connector_delivery_receipts
	    SET outbox_id = $3, status = 'containment_queued', reason = 'host containment retried',
	        detail = $5, updated_at = $6, latest_event_sequence = $7
	  WHERE tenant_id = $1 AND id = $2 AND identity_id = $4 AND destination = 'endpoint.contain'
	    AND coalesce(latest_event_sequence, 0) <= $7`,
		tenantID, receiptID, outboxID, identityID, detail, at.UTC(), seq)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var newer bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM connector_delivery_receipts
	   WHERE tenant_id=$1 AND id=$2 AND coalesce(latest_event_sequence,0) > $3)`,
		tenantID, receiptID, seq).Scan(&newer); err != nil {
		return err
	}
	if newer {
		return nil
	}
	return fmt.Errorf("store: key-compromise host retry names receipt %s that is not a retained containment receipt of identity %s", receiptID, identityID)
}

// RequeueDeadLetteredOutboxTx re-arms one exact dead-lettered outbox command in
// the caller's tenant transaction. Only a row in the terminal failed state with
// the expected destination and idempotency key is touched; the attempt count is
// kept so the history of the command stays visible. It returns whether the row
// changed; a pending row is left alone because the receiver still owns it.
func (s *Store) RequeueDeadLetteredOutboxTx(ctx context.Context, tx pgx.Tx, tenantID string,
	id int64, destination, idempotencyKey string) (bool, error) {
	if id <= 0 || destination == "" || idempotencyKey == "" {
		return false, errors.New("store: outbox requeue needs the exact row, destination and idempotency key")
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM outbox
	  WHERE tenant_id = $1 AND id = $2 AND destination = $3 AND idempotency_key = $4 FOR UPDATE`,
		tenantID, id, destination, idempotencyKey).Scan(&status); err != nil {
		return false, err
	}
	if status != "failed" {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE outbox
	    SET status = 'pending', next_attempt_at = now(), worker_id = NULL, lease_until = NULL,
	        claimed_by_agent_id = NULL, claim_expires_at = NULL, claim_completed_at = NULL
	  WHERE tenant_id = $1 AND id = $2 AND destination = $3 AND idempotency_key = $4 AND status = 'failed'`,
		tenantID, id, destination, idempotencyKey)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
