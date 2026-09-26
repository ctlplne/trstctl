// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Claiming precedes service admission. A different replica may finish erasure
// while this worker waits for a service session. Recheck the exact durable
// attempt under the shared service fence before any receiver call. Absence is
// not permission to deliver an in-memory message left over from an old tenant.
func (o *Outbox) beginRemoteDelivery(ctx context.Context, claim claimedOutboxEntry, attemptID string) error {
	var current bool
	err := o.store.WithTenant(ctx, claim.msg.TenantID, func(tx pgx.Tx) error {
		if err := o.store.TryTenantServiceAdmissionTx(ctx, tx, claim.msg.TenantID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE outbox SET receiver_pending_ids=array_append(receiver_pending_ids,$12::uuid)
			WHERE tenant_id=$1 AND id=$2 AND status='processing' AND worker_id=$3
			AND attempts=$4 AND lease_until>$5 AND destination=$6 AND idempotency_key=$7
			AND payload=$8 AND COALESCE(NULLIF(effect_lane,''),destination)=$9
			AND COALESCE(required_agent_role,'')=$10 AND retry_attempt_limit=$11`,
			claim.msg.TenantID, claim.id, o.workerID, claim.attempts, o.clockNow(),
			claim.msg.Destination, claim.msg.IdempotencyKey, claim.msg.Payload,
			claim.msg.EffectLane, claim.msg.RequiredAgentRole, claim.retryAttemptLimit, attemptID)
		current = tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return DeferDelivery(fmt.Errorf("orchestrator: verify delivery claim: %w", err))
	}
	if !current {
		return errOutboxClaimLost
	}
	return nil
}

func (o *Outbox) completeRemoteDelivery(ctx context.Context, claim claimedOutboxEntry, attemptID string) error {
	// A completed receiver result remains useful after request cancellation or
	// lease loss. This does not finalize a newer claim or clear any other token.
	// A durable terminal event may already have removed this same token.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return o.store.WithTenant(cleanup, claim.msg.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(cleanup, `UPDATE outbox
			SET receiver_pending_ids=array_remove(receiver_pending_ids,$3::uuid)
			WHERE tenant_id=$1 AND id=$2 AND destination=$4 AND idempotency_key=$5`,
			claim.msg.TenantID, claim.id, attemptID, claim.msg.Destination, claim.msg.IdempotencyKey)
		if err != nil {
			return fmt.Errorf("orchestrator: retain terminal receiver result: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return errors.New("orchestrator: terminal receiver attempt is missing")
		}
		return nil
	})
}
