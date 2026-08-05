// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/fleet"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// OpenAgentUpgradeCampaign starts a staged rollout (A5).
func (o *Orchestrator) OpenAgentUpgradeCampaign(ctx context.Context, tenantID, targetVersion, createdBy string) (store.AgentUpgradeCampaign, error) {
	if strings.TrimSpace(targetVersion) == "" {
		return store.AgentUpgradeCampaign{}, fmt.Errorf("orchestrator: an upgrade campaign needs a target version")
	}
	if _, active, err := o.store.ActiveAgentUpgradeCampaign(ctx, tenantID); err != nil {
		return store.AgentUpgradeCampaign{}, err
	} else if active {
		// Two concurrent rollouts to one fleet would each see the other's
		// agents as unexpectedly-versioned. One would halt on the other's work,
		// or worse, would not.
		return store.AgentUpgradeCampaign{}, fmt.Errorf(
			"orchestrator: a campaign is already active for this tenant; finish, halt, or cancel it " +
				"before starting another — two rollouts over one fleet cannot tell each other's " +
				"agents apart")
	}
	id := uuid.NewString()
	payload, err := json.Marshal(projections.AgentUpgradeCampaignOpened{
		ID: id, TargetVersion: strings.TrimSpace(targetVersion), CreatedBy: createdBy,
	})
	if err != nil {
		return store.AgentUpgradeCampaign{}, err
	}
	ev, err := o.emit(ctx, projections.EventAgentUpgradeCampaignOpened, tenantID, payload)
	if err != nil {
		return store.AgentUpgradeCampaign{}, err
	}
	return store.AgentUpgradeCampaign{
		ID: id, TenantID: tenantID, TargetVersion: targetVersion,
		Status: fleet.StatePending, CreatedBy: createdBy, CreatedAt: ev.Time,
	}, nil
}

// AdvanceAgentUpgradeCampaign records a campaign state change.
//
// The decision itself is fleet.Advance's; this only persists it. Keeping the
// rule in a pure function and the write here means a second caller cannot
// implement a slightly different halt.
func (o *Orchestrator) AdvanceAgentUpgradeCampaign(ctx context.Context, tenantID, id string, d fleet.Decision, haltedAt fleet.Ring) error {
	payload, err := json.Marshal(projections.AgentUpgradeCampaignAdvanced{
		ID: id, Status: d.NextState, CurrentRing: string(d.NextRing),
		HaltedAtRing: string(haltedAt), Reason: d.Reason,
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventAgentUpgradeCampaignAdvanced, tenantID, payload)
	return err
}

// AssignAgentUpgradeRing places an agent in a rollout ring.
func (o *Orchestrator) AssignAgentUpgradeRing(ctx context.Context, tenantID, agentID, ring string) error {
	switch fleet.Ring(ring) {
	case fleet.RingCanary, fleet.RingEarly, fleet.RingBroad:
	default:
		if ring != "" {
			return fmt.Errorf("orchestrator: %q is not a rollout ring; use canary, early, broad, or empty to unassign", ring)
		}
	}
	payload, err := json.Marshal(projections.AgentUpgradeRingAssigned{AgentID: agentID, Ring: ring})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventAgentUpgradeRingAssigned, tenantID, payload)
	return err
}
