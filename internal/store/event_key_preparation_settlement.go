// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SettleEventKeyPreparationTx is the verified activation's projection. Its
// caller authenticates retained source and current creation under the independent
// custody fence. Only this exact fixed key operation's invocation holds clear;
// status/worker/lease remain owned by the generic dispatcher.
func (s *Store) SettleEventKeyPreparationTx(ctx context.Context, tx pgx.Tx, command EventKeyPreparationCommand) error {
	if s == nil || tx == nil {
		return fmt.Errorf("store: event key settlement requires a store and transaction")
	}
	if err := command.Validate(); err != nil {
		return err
	}
	command.RequestedAt = command.RequestedAt.UTC()
	payload, err := json.Marshal(command)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE outbox SET receiver_pending_ids='{}'::uuid[]
	 WHERE tenant_id=$1 AND idempotency_key=$2 AND destination=$3
	 AND COALESCE(NULLIF(effect_lane,''),destination)=$3 AND payload=$4
	 AND required_agent_role='control_plane' AND required_agent_id IS NULL`,
		command.Ref.TenantID, EventKeyPreparationOutboxKey(command.Ref.ID), EventKeyPreparationDestination, payload)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2)`, command.Ref.TenantID, EventKeyPreparationOutboxKey(command.Ref.ID)).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: event key settlement command differs", ErrIdempotencyConflict)
	}
	return nil
}
