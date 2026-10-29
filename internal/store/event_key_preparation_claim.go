// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type EventKeyPreparationClaim struct {
	ID        int64
	AttemptID string
	Attempts  int
	Command   EventKeyPreparationCommand
}

// The generic dispatcher creates the invocation token only after claim and
// service admission. This independent read refuses direct or stale receiver
// calls, while the service fence excludes offboarding through the callback.
func (s *Store) WithEventKeyPreparationClaim(ctx context.Context, claim EventKeyPreparationClaim, visit func(context.Context) error) error {
	attempt, err := uuid.Parse(claim.AttemptID)
	if s == nil || visit == nil || claim.ID <= 0 || claim.Attempts <= 0 || err != nil || attempt.Version() != 4 || attempt.String() != claim.AttemptID || claim.Command.Validate() != nil {
		return errors.New("store: invalid event key preparation claim")
	}
	serviceCtx, release, err := s.BeginTenantService(ctx, claim.Command.Ref.TenantID)
	if err != nil {
		return err
	}
	defer release()
	if err := s.RequireLiveTenantService(serviceCtx, claim.Command.Ref.TenantID); err != nil {
		return err
	}
	claim.Command.RequestedAt = claim.Command.RequestedAt.UTC()
	payload, err := json.Marshal(claim.Command)
	if err != nil {
		return err
	}
	var current bool
	err = s.WithTenant(serviceCtx, claim.Command.Ref.TenantID, func(tx pgx.Tx) error {
		if err := s.TryTenantServiceAdmissionTx(serviceCtx, tx, claim.Command.Ref.TenantID); err != nil {
			return err
		}
		return tx.QueryRow(serviceCtx, `SELECT EXISTS(SELECT 1 FROM outbox
		 WHERE tenant_id=$1 AND id=$2 AND status='processing' AND attempts=$3
		 AND lease_until>clock_timestamp() AND destination=$4 AND idempotency_key=$5
		 AND payload=$6 AND COALESCE(NULLIF(effect_lane,''),destination)=$7
		 AND required_agent_role='control_plane' AND required_agent_id IS NULL
		 AND $8::uuid=ANY(receiver_pending_ids))`,
			claim.Command.Ref.TenantID, claim.ID, claim.Attempts,
			EventKeyPreparationDestination, EventKeyPreparationOutboxKey(claim.Command.Ref.ID),
			payload, EventKeyPreparationEffectLane, claim.AttemptID).Scan(&current)
	})
	if err != nil {
		return err
	}
	if !current {
		return errors.New("store: event key preparation invocation is not current")
	}
	if err := serviceCtx.Err(); err != nil {
		return err
	}
	return visit(serviceCtx)
}
