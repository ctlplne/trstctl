// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PendingCommandProjectionOperations snapshots only the exact older attempts
// visible before a canonical replay starts. A same-ID attempt that starts
// later must keep its own token until its outcome is independently checked.
func (s *Store) PendingCommandProjectionOperations(ctx context.Context, tenantID, eventID string) ([]string, error) {
	if s == nil {
		return nil, ErrRestoreActivityUnresolved
	}
	if eventID == "" {
		return nil, nil // no append token can be bound to an empty event ID
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, ErrRestoreActivityUnresolved
	}
	currentOperationID := uuid.Nil.String()
	if owner, ok := ctx.Value(keyStateOwnerContextKey{}).(*keyStateOwner); ok && owner != nil &&
		owner.store == s && owner.tenantID == tenantID {
		owner.mu.Lock()
		if operationID := owner.projectionActivities[eventID]; operationID != "" {
			currentOperationID = operationID
		}
		owner.mu.Unlock()
	}
	var operations []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT operation_id::text FROM trstctl_recovery.restore_activity_tokens
			WHERE tenant_id=$1 AND event_id=$2 AND activity_kind='projection'
			AND lane='command-apply' AND phase='started' AND operation_id<>$3
			ORDER BY operation_id`, tenantID, eventID, currentOperationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var operationID string
			if err := rows.Scan(&operationID); err != nil {
				return err
			}
			operations = append(operations, operationID)
		}
		return rows.Err()
	})
	return operations, err
}

// SettleReplayedCommandProjection closes only the pre-replay operations after
// the caller has authenticated the canonical source and completed both core
// and attached projections. A crash before this transaction leaves them
// pending so tail/recovery can repeat the exact canonical replay.
func (s *Store) SettleReplayedCommandProjection(ctx context.Context, tenantID, eventID string,
	operations []string,
) error {
	if s == nil || eventID == "" || len(operations) == 0 {
		return ErrRestoreActivityUnresolved
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return ErrRestoreActivityUnresolved
	}
	for _, operationID := range operations {
		if _, err := uuid.Parse(operationID); err != nil {
			return ErrRestoreActivityUnresolved
		}
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := s.LockGlobalKeyStateCommitTx(ctx, tx, KeyStateShared); err != nil {
			return err
		}
		if err := s.RequireRestoreProjectionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		var originalRole string
		if err := tx.QueryRow(ctx, `SELECT current_role`).Scan(&originalRole); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
			return err
		}
		for _, operationID := range operations {
			if _, err := tx.Exec(ctx, `UPDATE trstctl_recovery.restore_activity_tokens
				SET phase='terminal',terminal_at=now()
				WHERE tenant_id=$1 AND operation_id=$2 AND event_id=$3
				AND activity_kind='projection' AND lane='command-apply' AND phase='started'`,
				tenantID, operationID, eventID); err != nil {
				return fmt.Errorf("store: settle canonical command projection: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{originalRole}.Sanitize()); err != nil {
			return fmt.Errorf("store: restore role after canonical projection settlement: %w", err)
		}
		return s.AssertGlobalKeyStateAdmissionAlive(ctx)
	})
}
