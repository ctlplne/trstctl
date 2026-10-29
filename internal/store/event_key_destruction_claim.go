// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
)

type EventKeyDestructionClaim struct {
	ID        int64
	AttemptID string
	Attempts  int
	Command   eventprotect.DestructionRequest
}

// WithEventKeyDestructionClaim admits only the exact committed, leased
// invocation. It deliberately does not require a live tenant: SQL offboarding
// precedes this effect, and a newer registration may already own the UUID. The
// receiver must independently match the OLD retained lifetime and creation.
// No key I/O or external call occurs in this SQL transaction.
func (s *Store) WithEventKeyDestructionClaim(ctx context.Context, claim EventKeyDestructionClaim, visit func(context.Context) error) error {
	attempt, err := uuid.Parse(claim.AttemptID)
	if s == nil || visit == nil || claim.ID <= 0 || claim.Attempts <= 0 || err != nil || attempt.Version() != 4 || attempt.String() != claim.AttemptID || claim.Command.Validate() != nil {
		return errors.New("store: invalid event key destruction claim")
	}
	serviceCtx, release, err := s.BeginTenantService(ctx, claim.Command.Ref.TenantID)
	if err != nil {
		return err
	}
	defer release()
	claim.Command.OffboardedAt, claim.Command.NotBefore = claim.Command.OffboardedAt.UTC(), claim.Command.NotBefore.UTC()
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
		 AND payload=$6 AND COALESCE(NULLIF(effect_lane,''),destination)=$4
		 AND required_agent_role='control_plane' AND required_agent_id IS NULL
		 AND $7::uuid=ANY(receiver_pending_ids))`,
			claim.Command.Ref.TenantID, claim.ID, claim.Attempts,
			EventKeyDestructionDestination, EventKeyDestructionOutboxKey(claim.Command.OperationID), payload, claim.AttemptID).Scan(&current)
	})
	if err != nil {
		return err
	}
	if !current {
		return errors.New("store: event key destruction invocation is not current")
	}
	if err := serviceCtx.Err(); err != nil {
		return err
	}
	return visit(serviceCtx)
}

// RequireEventKeyDestructionService is ONLY for the separate exact-destination
// dispatcher. Keep RequireLiveTenantService on every normal dispatcher. This
// precheck grants no effect: its receiver still verifies the full invocation
// and source/current-custody authority before touching that historical key.
func (s *Store) RequireEventKeyDestructionService(ctx context.Context, tenantID string) error {
	var current bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM outbox WHERE tenant_id=$1
		 AND destination=$2 AND COALESCE(NULLIF(effect_lane,''),destination)=$2
		 AND required_agent_role='control_plane' AND required_agent_id IS NULL
		 AND status='processing' AND lease_until>clock_timestamp()
		 AND cardinality(receiver_pending_ids)>0)`, tenantID, EventKeyDestructionDestination).Scan(&current)
	})
	if err != nil {
		return err
	}
	if !current {
		return errors.New("store: no current dedicated event key destruction invocation")
	}
	return nil
}
