// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// functionalCheckState is where one agent's post-upgrade self-check stands.
type functionalCheckState int

const (
	// checkPending: queued and inside its grace; not evidence either way.
	checkPending functionalCheckState = iota
	// checkPassed: the agent's signed receipt says every check passed.
	checkPassed
	// checkFailed: the agent's signed receipt says a check failed.
	checkFailed
	// checkSilent: queued, past the grace, never answered.
	checkSilent
)

// functionalCheck queues the agent's post-upgrade self-check (A71) the first
// time the sweep sees the agent on the target build, and scores it afterwards.
// The key is derived from the upgrade dispatch (or the campaign ring in
// observe-only mode), so a replayed sweep re-asks nothing; the row is pinned
// to the agent, so only that agent can answer it.
func (s *Server) functionalCheck(
	ctx context.Context, tenantID string, c store.AgentUpgradeCampaign, ring fleet.Ring,
	agentID, key string, cutoff time.Time,
) (functionalCheckState, error) {
	if s.outbox == nil {
		return checkPending, errors.New("server: agent self-check needs the outbox")
	}
	status, found, err := s.store.AgentSelfCheckStatus(ctx, tenantID, key)
	if err != nil {
		return checkPending, err
	}
	if !found {
		intent, err := json.Marshal(relay.SelfCheckIntent{
			CampaignID: c.ID, Ring: string(ring), Round: c.DispatchRound, TargetVersion: c.TargetVersion,
		})
		if err != nil {
			return checkPending, err
		}
		return checkPending, s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: store.AgentSelfCheckDestination,
				IdempotencyKey: key, Payload: intent, RequiredAgentID: agentID,
			})
			return err
		})
	}
	switch status.Outcome {
	case "executed":
		return checkPassed, nil
	case upgradeReceiptFailed:
		return checkFailed, nil
	}
	if status.DispatchedAt.After(cutoff) {
		return checkPending, nil
	}
	return checkSilent, nil
}

// selfCheckKeyForDispatch keys the functional check off the upgrade job it
// follows, so a resumed round asks again and the old round's answer stops
// counting.
func selfCheckKeyForDispatch(jobKey string) string { return jobKey + ":selfcheck" }

// selfCheckKeyForRing keys an observe-only campaign's check by ring: nothing
// was dispatched, so the ring itself is the round.
func selfCheckKeyForRing(campaignID string, ring fleet.Ring, agentID string) string {
	return fmt.Sprintf("agent-selfcheck:%s:%s:%s", campaignID, ring, agentID)
}
