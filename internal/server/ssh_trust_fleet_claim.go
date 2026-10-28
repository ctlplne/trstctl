// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

// projectSSHTrustFleetClaim requires the immutable approved source as well as
// the tenant/role/host-scoped SQL lease. A fabricated derived outbox row cannot
// become an instruction to change sshd merely because it has a valid payload.
func (a *agentService) projectSSHTrustFleetClaim(ctx context.Context, job store.AgentJob) ([]byte, error) {
	command, err := sshtrustrollout.DecodeCommand(bytes.NewReader(job.Payload))
	if err != nil {
		return nil, err
	}
	refuse := func() ([]byte, error) {
		return nil, errors.New("SSH trust claim has no matching approved source or its execution window ended")
	}
	if a.log == nil || job.IdempotencyKey != orchestrator.SSHTrustFleetJobKey(command.RolloutID, command.AgentID) || !time.Now().UTC().Before(command.ExpiresAt) {
		return refuse()
	}
	event, found, err := a.log.EventByID(ctx, command.RolloutID)
	if err != nil {
		return nil, err
	}
	if !found || event.TenantID != job.TenantID || event.Type != projections.EventSSHTrustFleetStarted || event.SchemaVersion != 1 {
		return refuse()
	}
	var started projections.SSHTrustFleetStarted
	if json.Unmarshal(event.Data, &started) != nil || projections.ValidateSSHTrustFleetStarted(started) != nil || started.ID != command.RolloutID || started.ID != orchestrator.SSHTrustFleetRolloutID(job.TenantID, started.Approval.RequestID) || started.PlanDigest != command.PlanDigest || started.Plan.CAFingerprint != command.CAFingerprint || !bytes.Equal(started.Plan.PublicCAKey, command.PublicCAKey) || !started.Plan.ExpiresAt.Equal(command.ExpiresAt) {
		return refuse()
	}
	for _, host := range started.Plan.Hosts {
		if host.AgentID == command.AgentID && host.State == "ready" && host.ReadinessDigest == command.ReadinessDigest {
			return job.Payload, nil
		}
	}
	return refuse()
}
