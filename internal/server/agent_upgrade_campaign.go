// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/fleet"
)

const (
	// campaignSweepInterval bounds how quickly a ring's result is noticed.
	campaignSweepInterval = time.Minute
	// campaignVerifyGrace is how long a ring gets to come back before silence
	// counts against it. Shorter than this and a slow box halts a good rollout;
	// longer and a broken build sits undetected.
	campaignVerifyGrace = 10 * time.Minute
)

// RunAgentUpgradeCampaignOnce advances the tenant's campaign by one step.
//
// Verification is "the agent came back and reported the target version, and has
// been seen since it was dispatched". That is a genuine post-upgrade health
// signal — an agent that took a bad build and cannot start never reports it —
// but it is NOT a functional check of the agent's work, and the docs say so
// rather than letting "verified" imply more than it proves.
func (s *Server) RunAgentUpgradeCampaignOnce(ctx context.Context, tenantID string) error {
	c, active, err := s.store.ActiveAgentUpgradeCampaign(ctx, tenantID)
	if err != nil || !active {
		return err
	}
	if !fleet.CanDispatch(c.Status) {
		// Halted or paused. Returning here is what makes the console's pause
		// real: a pause that only greyed out a button while this loop kept
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
	outcome := fleet.RingOutcome{Ring: ring, Dispatched: len(agents)}
	cutoff := time.Now().UTC().Add(-campaignVerifyGrace)
	waiting := false
	for _, a := range agents {
		switch {
		case a.Version == c.TargetVersion:
			outcome.Verified++
		case a.LastSeenAt != nil && a.LastSeenAt.After(cutoff):
			// Seen recently but still on the old version: it is mid-upgrade,
			// not failed. Counting it against the ring now would halt every
			// rollout on its own dispatch latency.
			waiting = true
		}
	}
	if waiting {
		return nil
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
