// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// OpenAgentUpgradeCampaign starts a staged rollout (A5).
//
// artifacts may be empty: that opens an OBSERVE-ONLY campaign, which gates
// rings on the versions the fleet reports while something else moves agents —
// the only mode that existed before dispatch was built. With artifacts, the
// sweep dispatches agent.upgrade jobs ring by ring and the fleet moves itself.
func (o *Orchestrator) OpenAgentUpgradeCampaign(ctx context.Context, tenantID, targetVersion, createdBy string, artifacts []fleet.Artifact) (store.AgentUpgradeCampaign, error) {
	if strings.TrimSpace(targetVersion) == "" {
		return store.AgentUpgradeCampaign{}, fmt.Errorf("orchestrator: an upgrade campaign needs a target version")
	}
	if err := fleet.ValidateArtifacts(artifacts); err != nil {
		return store.AgentUpgradeCampaign{}, fmt.Errorf("orchestrator: %w", err)
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
		Artifacts: artifacts,
	})
	if err != nil {
		return store.AgentUpgradeCampaign{}, err
	}
	ev, err := o.emit(ctx, projections.EventAgentUpgradeCampaignOpened, tenantID, payload)
	if err != nil {
		return store.AgentUpgradeCampaign{}, err
	}
	encoded, err := fleet.EncodeArtifacts(artifacts)
	if err != nil {
		return store.AgentUpgradeCampaign{}, err
	}
	return store.AgentUpgradeCampaign{
		ID: id, TenantID: tenantID, TargetVersion: targetVersion,
		Status: fleet.StatePending, CreatedBy: createdBy, ArtifactsJSON: encoded, CreatedAt: ev.Time,
	}, nil
}

// DispatchAgentUpgradeRing hands every agent in a ring its own agent.upgrade
// job (A5). One event records the round; the outbox rows are enqueued in the
// same transaction the event projects in (AN-6), keyed deterministically by
// (campaign, round, agent) so a replayed event re-derives exactly the same
// rows and a crash between append and enqueue heals without a double dispatch.
func (o *Orchestrator) DispatchAgentUpgradeRing(
	ctx context.Context, tenantID string, c store.AgentUpgradeCampaign,
	ring fleet.Ring, round int, agents []store.Agent, artifacts []fleet.Artifact,
) error {
	if len(agents) == 0 {
		return fmt.Errorf("orchestrator: refusing to dispatch an empty %s ring", ring)
	}
	jobs := make([]projections.UpgradeJobRef, 0, len(agents))
	for _, a := range agents {
		jobs = append(jobs, projections.UpgradeJobRef{
			AgentID: a.ID,
			JobKey:  fmt.Sprintf("agent-upgrade:%s:%d:%s", c.ID, round, a.ID),
		})
	}
	payload, err := json.Marshal(projections.AgentUpgradeRingDispatched{
		CampaignID: c.ID, Ring: string(ring), Round: round,
		TargetVersion: c.TargetVersion, Artifacts: artifacts, Jobs: jobs,
	})
	if err != nil {
		return err
	}
	intent, err := json.Marshal(fleet.UpgradeIntent{
		CampaignID: c.ID, Ring: string(ring), Round: round,
		TargetVersion: c.TargetVersion, Artifacts: artifacts,
	})
	if err != nil {
		return err
	}
	eventID := events.NewID()
	return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventAgentUpgradeRingDispatched,
			TenantID: tenantID, SchemaVersion: 1, Data: payload,
		})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		for _, j := range jobs {
			// EnqueueIfAbsent, not Enqueue: the deterministic key makes a
			// replay (or the crash-heal path re-running this event) a no-op
			// rather than a second order to the same agent.
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID:        tenantID,
				Destination:     agentUpgradeDestination,
				IdempotencyKey:  j.JobKey,
				Payload:         intent,
				RequiredAgentID: j.AgentID,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// agentUpgradeDestination is the outbox destination/job kind for agent
// self-upgrades (A5). The dispatcher's claim SQL refuses every row that
// demands a specific agent, so these rows are reachable only through
// ClaimAgentJobs — by exactly the agent each row names.
const agentUpgradeDestination = "agent.upgrade"

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
