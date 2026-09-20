// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RecordConnectorRollbackResult records only the result of the current signed
// claim. Retirement and its later callback can straddle an operator re-arm; the
// old callback must not publish success for the new pending command. Request and
// result writers lock the same tenant/job row through event append and projection.
func (o *Orchestrator) RecordConnectorRollbackResult(ctx context.Context, tenantID, jobKey string, attempt int, r store.ConnectorDeliveryReceipt) error {
	if r.OutboxID == nil || *r.OutboxID <= 0 || attempt <= 0 || jobKey == "" || r.Destination != DestinationConnectorRollback {
		return errors.New("orchestrator: rollback result requires its exact job and signed attempt")
	}
	if r.Status != "rolled_back" && r.Status != "rollback_failed" && r.Status != "rollback_refused" {
		return errors.New("orchestrator: rollback result has an invalid status")
	}
	return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var status string
		var currentAttempt int
		var completed, released bool
		err := tx.QueryRow(ctx, `SELECT status, claim_attempts,
    claim_completed_at IS NOT NULL,
    claimed_by_agent_id IS NULL AND last_error IS NOT NULL
   FROM outbox WHERE tenant_id=$1 AND id=$2 AND destination=$3 AND idempotency_key=$4
   FOR UPDATE`, tenantID, *r.OutboxID, DestinationConnectorRollback, jobKey).
			Scan(&status, &currentAttempt, &completed, &released)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		// Rearm clears completion/error without resetting claim_attempts. A later
		// claim increments that counter. Both boundaries invalidate the old result.
		terminal := completed && (status == "delivered" || status == "failed")
		retryFailure := status == "pending" && released && r.Status != "rolled_back"
		if currentAttempt != attempt || (!terminal && !retryFailure) || (r.Status == "rolled_back" && status != "delivered") {
			return nil
		}
		if r.ID == "" {
			r.ID = uuid.NewString()
		}
		payload, err := json.Marshal(projections.ConnectorDeliveryRecorded{
			ID: r.ID, OutboxID: r.OutboxID, IdentityID: r.IdentityID,
			Destination: DestinationConnectorRollback, Connector: r.Connector, Target: r.Target,
			Fingerprint: r.Fingerprint, Status: r.Status, Attempts: attempt,
			Reason: r.Reason, Detail: r.Detail, RollbackRef: r.RollbackRef,
			IdempotencyKey: jobKey + ":rollback-result",
		})
		if err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventConnectorDeliveryRecorded, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	})
}
