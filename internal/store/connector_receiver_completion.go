// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ApplyConnectorReceiverCompletedTx projects the terminal lifetime fact in the
// same transaction as its delivery receipt. An interrupted inline projection
// can therefore recover from the retained event without repeating receiver I/O.
// Historical receipts and failed deliveries prove no particular call stopped.
func (s *Store) ApplyConnectorReceiverCompletedTx(ctx context.Context, tx pgx.Tx, r ConnectorDeliveryReceipt, attemptID string) error {
	if attemptID == "" || r.Status != "delivered" {
		return nil
	}
	id, err := uuid.Parse(attemptID)
	if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 ||
		r.OutboxID == nil || *r.OutboxID <= 0 || r.Destination != "connector.deploy" || r.IdempotencyKey == "" {
		return errors.New("store: connector receiver completion has an invalid invocation binding")
	}
	// Remove only the event's invocation. A successful retry is not evidence
	// about an earlier timed-out call, and must never clear the legacy sentinel.
	tag, err := tx.Exec(ctx, `UPDATE outbox
		SET receiver_pending_ids=array_remove(receiver_pending_ids,$3::uuid)
		WHERE tenant_id=$1 AND id=$2 AND destination=$4 AND idempotency_key=$5`,
		r.TenantID, *r.OutboxID, attemptID, r.Destination, r.IdempotencyKey)
	if err != nil {
		return fmt.Errorf("store: project connector receiver completion: %w", err)
	}
	if tag.RowsAffected() != 0 {
		return nil
	}
	// Rebuild, retention, or completed erasure can leave no outbox row. Do not
	// recreate it. A surviving row with different authority is corruption.
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM outbox WHERE tenant_id=$1 AND id=$2)`, r.TenantID, *r.OutboxID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return errors.New("store: connector receiver completion does not match its outbox command")
	}
	return nil
}
