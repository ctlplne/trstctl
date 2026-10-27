// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/store"
)

const (
	// campaignSweepInterval bounds how quickly a ring's result is noticed.
	campaignSweepInterval = time.Minute
	// campaignVerifyGrace is how long a dispatched agent gets to come back on
	// the target version before silence counts against it. Shorter than this
	// and a slow box halts a good rollout; longer and a broken build sits
	// undetected.
	campaignVerifyGrace = 10 * time.Minute
	// upgradeReceiptFailed is the outcome field of a signature-verified receipt
	// reporting the upgrade failed (the agent_job_receipts vocabulary, epic A1).
	upgradeReceiptFailed = "failed"
)

// RunAgentUpgradeCampaignOnce advances the tenant's campaign by one step.
//
// Two modes, decided by whether the campaign published artifacts:
//
//   - DISPATCHING (artifacts present): the sweep hands every agent in the
//     active ring its own agent.upgrade job through the ledger, then scores
//     the ring against those dispatches. A failed SIGNED receipt halts
//     immediately; an agent observed on the target version verifies; an agent
//     that neither failed nor arrived within the grace window is silent, and
//     silence halts.
//   - OBSERVE-ONLY (no artifacts): the pre-dispatch behavior, kept for fleets
//     an external mechanism upgrades. Verification is "the agent reports the
//     target version"; an agent seen recently on the old version is treated as
//     mid-upgrade and waited for. This mode has no dispatch timestamp, so it
//     has no deadline — it gates, it cannot push.
//
// In both modes the REFUSALS live in fleet.Advance; this function only
// assembles the ring's outcome and persists the decision.
func (s *Server) RunAgentUpgradeCampaignOnce(ctx context.Context, tenantID string) error {
	c, active, err := s.store.ActiveAgentUpgradeCampaign(ctx, tenantID)
	if err != nil || !active {
		return err
	}
	if !fleet.CanDispatch(c.Status) {
		// Halted or paused. Returning here is what makes the console's pause
		// real: a pause that only grayed out a button while this loop kept
		// dispatching would be worse than none.
		return nil
	}
	ring := fleet.Ring(c.CurrentRing)
	if ring == "" {
		ring = fleet.Rings[0]
	}
	agents, err := s.store.AgentsInRing(ctx, tenantID, string(ring))
	if err != nil {
		return err
	}
	if len(agents) == 0 {
		// An empty ring is not a verified ring. Advancing through it would let
		// a rollout skip its canary entirely whenever nobody assigned one —
		// which is exactly the fleet where a canary matters most.
		d := fleet.Decision{
			NextState: fleet.StateHalted,
			Reason: "Halted: the " + string(ring) + " ring has no agents assigned. An empty ring " +
				"proves nothing, and advancing through it would skip the stage whose failure is " +
				"supposed to stop this rollout.",
		}
		return s.orch.AdvanceAgentUpgradeCampaign(ctx, tenantID, c.ID, d, ring)
	}

	artifacts, err := fleet.DecodeArtifacts(c.ArtifactsJSON)
	if err != nil {
		return fmt.Errorf("server: campaign %s carries undecodable artifacts: %w", c.ID, err)
	}
	if len(artifacts) > 0 {
		return s.stepDispatchingCampaign(ctx, tenantID, c, ring, agents, artifacts)
	}
	return s.stepObserveOnlyCampaign(ctx, tenantID, c, ring, agents)
}

// stepDispatchingCampaign is one sweep step for a campaign that owns its
// rollout: dispatch the ring if it has not been, otherwise score it against
// its dispatch ledger and receipts.
func (s *Server) stepDispatchingCampaign(
	ctx context.Context, tenantID string, c store.AgentUpgradeCampaign,
	ring fleet.Ring, agents []store.Agent, artifacts []fleet.Artifact,
) error {
	if c.DispatchedRing != string(ring) {
		// The current ring has no live dispatch round. This is both the normal
		// entry path (campaign opened, ring advanced, resume after a halt) and
		// the crash-heal path: a crash between "ring entered" and "jobs
		// enqueued" lands here on the next sweep and dispatches then.
		round := c.DispatchRound + 1
		s.logger.Info("dispatching agent upgrade ring",
			slog.String("tenant_id", tenantID), slog.String("campaign_id", c.ID),
			slog.String("ring", string(ring)), slog.Int("round", round),
			slog.Int("agents", len(agents)))
		return s.orch.DispatchAgentUpgradeRing(ctx, tenantID, c, ring, round, agents, artifacts)
	}

	statuses, err := s.store.AgentUpgradeDispatchStatuses(ctx, tenantID, c.ID, c.DispatchRound)
	if err != nil {
		return err
	}
	if len(statuses) == 0 {
		// The stamp says dispatched but the ledger has no rows yet — projection
		// lag on another node. Waiting is the only honest read.
		return nil
	}
	// The DISPATCHES are the denominator, not current ring membership: an agent
	// moved into the ring after dispatch was never told to upgrade and must not
	// be scored silent; one moved out was told, and still counts.
	outcome := fleet.RingOutcome{Ring: ring, Dispatched: len(statuses)}
	cutoff := time.Now().UTC().Add(-campaignVerifyGrace)
	waiting := false
	for _, st := range statuses {
		switch {
		case st.ReceiptOutcome == upgradeReceiptFailed:
			// The agent's own signed statement that the upgrade failed. This
			// is the fastest halt signal — no grace applies to an explicit
			// failure.
			outcome.Failed++
		case st.AgentVersion == c.TargetVersion:
			// The agent is RUNNING the target build and the control plane has
			// heard from it. An executed receipt alone is only "staged"; the
			// version report is the proof the new build came back up — and
			// A71 asks one more thing of it: the functional self-check it is
			// queued the first time it is seen here, which it must pass.
			state, err := s.functionalCheck(ctx, tenantID, c, ring, st.AgentID, selfCheckKeyForDispatch(st.JobKey), cutoff)
			if err != nil {
				return err
			}
			switch state {
			case checkPassed:
				outcome.Verified++
			case checkFailed:
				outcome.CheckFailed++
			case checkPending:
				waiting = true
			}
			// checkSilent: on the target build but never answered its check
			// within the grace; Silent() counts it.
		case st.DispatchedAt.After(cutoff):
			// Dispatched recently, no verdict yet: downloading, restarting, or
			// simply not polling this second. Mid-grace is not evidence.
			waiting = true
		}
		// Neither failed, nor on target, nor within grace: silent. An agent
		// that took an upgrade order and never came back on the new version is
		// the most likely shape of a bad build, and Silent() computes it from
		// the counts above.
	}
	if outcome.Failed == 0 && outcome.CheckFailed == 0 && waiting {
		// No failures and at least one agent still inside its grace: wait. A
		// failure short-circuits the wait — one signed "failed" is enough and
		// the rest of the ring cannot un-fail it.
		return nil
	}
	if outcome.Failed == 0 && outcome.CheckFailed == 0 && outcome.Silent() == 0 {
		// A70: every dispatched agent is on the target build. Before the next
		// ring, the campaign's soak window must pass with the ring still
		// healthy: a build that came up and degrades minutes later must not
		// reach the next ring first. An agent that stops heartbeating during
		// the soak is silence, and silence halts.
		var latest time.Time
		for _, st := range statuses {
			if st.DispatchedAt.After(latest) {
				latest = st.DispatchedAt
			}
			if st.AgentLastSeen == nil || st.AgentLastSeen.Before(cutoff) {
				outcome.Verified--
			}
		}
		if outcome.Silent() == 0 {
			if until, soaking := fleet.SoakPending(c.SoakSeconds, latest, time.Now().UTC()); soaking {
				return s.recordSoak(ctx, tenantID, c, ring, until)
			}
		}
	}
	d := fleet.Advance(c.Status, outcome)
	haltedAt := fleet.Ring("")
	if d.NextState == fleet.StateHalted {
		haltedAt = ring
	}
	if d.NextState == c.Status && d.NextRing == ring {
		return nil
	}
	s.logger.Info("agent upgrade campaign advanced",
		slog.String("tenant_id", tenantID), slog.String("campaign_id", c.ID),
		slog.String("status", d.NextState), slog.String("reason", d.Reason))
	return s.orch.AdvanceAgentUpgradeCampaign(ctx, tenantID, c.ID, d, haltedAt)
}

// stepObserveOnlyCampaign scores a ring for a campaign with no artifacts: the
// pre-dispatch mode, where something else moves agents onto the version and
// this loop only gates.
//
// Verification is "the agent came back and reported the target version, has
// been seen since, and passed the functional self-check queued for it" (A71).
// The version report is a genuine post-upgrade health signal — an agent that
// took a bad build and cannot start never reports it — and the self-check is
// what makes verified mean the agent still does its work.
func (s *Server) stepObserveOnlyCampaign(
	ctx context.Context, tenantID string, c store.AgentUpgradeCampaign,
	ring fleet.Ring, agents []store.Agent,
) error {
	outcome := fleet.RingOutcome{Ring: ring, Dispatched: len(agents)}
	cutoff := time.Now().UTC().Add(-campaignVerifyGrace)
	waiting := false
	for _, a := range agents {
		switch {
		case a.Version == c.TargetVersion:
			state, err := s.functionalCheck(ctx, tenantID, c, ring, a.ID, selfCheckKeyForRing(c.ID, ring, a.ID), cutoff)
			if err != nil {
				return err
			}
			switch state {
			case checkPassed:
				outcome.Verified++
			case checkFailed:
				outcome.CheckFailed++
			case checkPending:
				waiting = true
			}
		case a.LastSeenAt != nil && a.LastSeenAt.After(cutoff):
			// Seen recently but still on the old version: it is mid-upgrade,
			// not failed. Counting it against the ring now would halt every
			// rollout on its own dispatch latency.
			waiting = true
		}
	}
	if waiting && outcome.CheckFailed == 0 {
		return nil
	}
	if outcome.Failed == 0 && outcome.CheckFailed == 0 && outcome.Silent() == 0 {
		// A70, observe-only: the soak clock starts when the campaign entered
		// this ring (its last state change); an agent not seen within the grace
		// during the soak is silence.
		for _, a := range agents {
			if a.LastSeenAt == nil || a.LastSeenAt.Before(cutoff) {
				outcome.Verified--
			}
		}
		if outcome.Silent() == 0 {
			if until, soaking := fleet.SoakPending(c.SoakSeconds, c.UpdatedAt, time.Now().UTC()); soaking {
				return s.recordSoak(ctx, tenantID, c, ring, until)
			}
		}
	}
	d := fleet.Advance(c.Status, outcome)
	haltedAt := fleet.Ring("")
	if d.NextState == fleet.StateHalted {
		haltedAt = ring
	}
	if d.NextState == c.Status && d.NextRing == ring {
		return nil
	}
	s.logger.Info("agent upgrade campaign advanced",
		slog.String("tenant_id", tenantID), slog.String("campaign_id", c.ID),
		slog.String("status", d.NextState), slog.String("reason", d.Reason))
	return s.orch.AdvanceAgentUpgradeCampaign(ctx, tenantID, c.ID, d, haltedAt)
}

// RunAgentUpgradeCampaigns is the leader-only ticker.
func (s *Server) RunAgentUpgradeCampaigns(ctx context.Context) {
	if s.store == nil || s.orch == nil {
		return
	}
	sweep := func() {
		tenants, err := s.store.ListTenants(ctx)
		if err != nil {
			s.logger.Warn("upgrade campaign sweep: list tenants failed", slog.String("error", err.Error()))
			return
		}
		for _, t := range tenants {
			if err := s.RunAgentUpgradeCampaignOnce(ctx, t.TenantID); err != nil {
				s.logger.Warn("upgrade campaign sweep failed",
					slog.String("tenant_id", t.TenantID), slog.String("error", err.Error()))
			}
		}
	}
	sweep()
	tk := time.NewTicker(campaignSweepInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			sweep()
		}
	}
}

// recordSoak serves the soak as the campaign's reason exactly once per ring:
// the operator reads when the ring may advance instead of a running campaign
// that appears stuck. Later sweeps inside the window change nothing.
//
// The decision keeps the ring, so the projection records it as the same ring
// entry (ApplyAgentUpgradeCampaignAdvancedTx): the window keeps its start, and
// a dispatched ring keeps its round instead of being dispatched again.
func (s *Server) recordSoak(ctx context.Context, tenantID string, c store.AgentUpgradeCampaign, ring fleet.Ring, until time.Time) error {
	reason := fleet.SoakReason(ring, until)
	if c.Reason == reason {
		return nil
	}
	s.logger.Info("agent upgrade ring soaking",
		slog.String("tenant_id", tenantID), slog.String("campaign_id", c.ID),
		slog.String("ring", string(ring)), slog.String("until", until.UTC().Format(time.RFC3339)))
	return s.orch.AdvanceAgentUpgradeCampaign(ctx, tenantID, c.ID,
		fleet.Decision{NextState: fleet.StateRunning, NextRing: ring, Reason: reason}, "")
}
