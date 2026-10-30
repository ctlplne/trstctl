// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
)

func (s *Store) SettleEventKeyDestructionTx(ctx context.Context, tx pgx.Tx, request eventprotect.DestructionRequest) error {
	if s == nil || tx == nil || request.Validate() != nil {
		return fmt.Errorf("store: invalid event key destruction settlement")
	}
	request.OffboardedAt, request.NotBefore = request.OffboardedAt.UTC(), request.NotBefore.UTC()
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE outbox SET receiver_pending_ids='{}'::uuid[]
	 WHERE tenant_id=$1 AND idempotency_key=$2 AND destination=$3
	 AND COALESCE(NULLIF(effect_lane,''),destination)=$3 AND payload=$4
	 AND required_agent_role='control_plane' AND required_agent_id IS NULL`, request.Ref.TenantID, EventKeyDestructionOutboxKey(request.OperationID), EventKeyDestructionDestination, payload)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2)`, request.Ref.TenantID, EventKeyDestructionOutboxKey(request.OperationID)).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: event key destruction settlement command differs", ErrIdempotencyConflict)
	}
	return nil
}

// RemoveSettledEventKeyDestructionTx runs only after independent verification,
// after generic delivery finalization. It removes at most ONE exact row; neither
// a current/new tenant lifetime nor another destination can match this command.
func (s *Store) RemoveSettledEventKeyDestructionTx(ctx context.Context, tx pgx.Tx, request eventprotect.DestructionRequest) (bool, error) {
	if s == nil || tx == nil || request.Validate() != nil {
		return false, fmt.Errorf("store: invalid event key destruction cleanup")
	}
	request.OffboardedAt, request.NotBefore = request.OffboardedAt.UTC(), request.NotBefore.UTC()
	payload, err := json.Marshal(request)
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 AND destination=$3
	 AND COALESCE(NULLIF(effect_lane,''),destination)=$3 AND payload=$4
	 AND required_agent_role='control_plane' AND required_agent_id IS NULL
	 AND status='delivered' AND cardinality(receiver_pending_ids)=0`, request.Ref.TenantID, EventKeyDestructionOutboxKey(request.OperationID), EventKeyDestructionDestination, payload)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
