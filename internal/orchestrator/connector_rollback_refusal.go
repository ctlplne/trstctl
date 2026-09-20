// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RefuseUnsafeConnectorRollbackClaim records a control-plane refusal and retires
// its exact claim in one transaction. It never invents an agent execution or a
// signed agent receipt. If evidence cannot be persisted, the job stays leased
// and is reconsidered after expiry rather than disappearing without a result.
func (o *Orchestrator) RefuseUnsafeConnectorRollbackClaim(ctx context.Context, tenantID, agentID string, job store.AgentJob, at time.Time) error {
	return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var payload []byte
		var jobKey string
		err := tx.QueryRow(ctx, `SELECT payload, idempotency_key FROM outbox
		 WHERE tenant_id=$1 AND id=$2 AND destination=$3 AND claimed_by_agent_id=$4::uuid
		 AND claim_attempts=$5 AND claim_completed_at IS NULL AND status='pending'
		 AND claim_expires_at>$6 FOR UPDATE`, tenantID, job.ID, DestinationConnectorRollback, agentID, job.ClaimAttempts, at.UTC()).Scan(&payload, &jobKey)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var req ConnectorRollbackRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return err
		}
		var identityID *string
		if req.IdentityID != "" {
			identityID = &req.IdentityID
		}
		id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("rollback-policy-refusal:%s:%d:%d", tenantID, job.ID, job.ClaimAttempts))).String()
		data, err := json.Marshal(projections.ConnectorDeliveryRecorded{
			ID: id, OutboxID: &job.ID, IdentityID: identityID,
			Destination: DestinationConnectorRollback, Connector: req.Connector, Target: req.Target,
			Fingerprint: req.PredecessorFingerprint, Status: "rollback_refused", Attempts: job.ClaimAttempts,
			Reason: "rollback_refused_by_control_plane", Detail: store.ErrUnsafeRollback.Error() + ". The control plane withheld the job before agent execution.",
			IdempotencyKey: jobKey + ":rollback-result",
		})
		if err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{ID: id, TenantID: tenantID, Type: projections.EventConnectorDeliveryRecorded, Data: data})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE outbox SET status='failed', claimed_by_agent_id=NULL,
		 claim_expires_at=NULL, claim_completed_at=$3, attempts=attempts+1, last_error=$4
		 WHERE tenant_id=$1 AND id=$2`, tenantID, job.ID, at.UTC(), store.ErrUnsafeRollback.Error()); err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	})
}
