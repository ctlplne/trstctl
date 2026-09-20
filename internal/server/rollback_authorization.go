// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Recheck durable work before sending it to an agent. Queue-time authorization
// cannot authorize a rollback that waited through a later revocation.
func (a *agentService) checkClaimedRollback(ctx context.Context, tenantID, agentID string, job store.AgentJob) (bool, error) {
	if job.Destination != orchestrator.DestinationConnectorRollback {
		return true, nil
	}
	err := a.store.CheckConnectorRollbackPayload(ctx, tenantID, job.Payload)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, store.ErrUnsafeRollback) {
		return false, err
	}
	if a.orch == nil {
		return false, errors.New("rollback refusal recorder is unavailable")
	}
	return false, a.orch.RefuseUnsafeConnectorRollbackClaim(ctx, tenantID, agentID, job, time.Now().UTC())
}
