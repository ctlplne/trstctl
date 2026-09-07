// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"

	"errors"
	"fmt"
	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/orchestrator"
)

type upgradeCampaignBody struct {
	TargetVersion string `json:"target_version"`
	// Artifacts turns the campaign from observe-only into a rollout that
	// DISPATCHES: one downloadable build per platform, each pinned by its
	// sha256. Omitted = observe-only, the pre-dispatch behaviour.
	Artifacts []fleet.Artifact `json:"artifacts,omitempty"`
}

type ringAssignBody struct {
	AgentID string `json:"agent_id"`
	Ring    string `json:"ring"`
}

type upgradeCampaignResponse struct {
	ID            string `json:"id,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`
	// Active distinguishes "no campaign has ever run" from "one is running".
	Active bool   `json:"active"`
	Status string `json:"status,omitempty"`
	// CurrentRing and HaltedAtRing are both served: an operator needs to know
	// where a resume would restart, which is the halted ring and not the next.
	CurrentRing  string `json:"current_ring,omitempty"`
	HaltedAtRing string `json:"halted_at_ring,omitempty"`
	// Reason explains a halt. "halted" alone sends somebody to read logs.
	Reason string `json:"reason,omitempty"`
	// Rings and Versions are the fleet's shape. Unassigned is a key in Rings
	// and is never folded into broad.
	Rings    map[string]int `json:"rings"`
	Versions map[string]int `json:"versions"`
	// ObserveOnly says whether this campaign merely gates (no artifacts were
	// published) or dispatches agent.upgrade jobs itself. Served so the
	// console can say which one the operator actually started — a gating
	// campaign that looks like a pushing one reads as a rollout that hangs.
	ObserveOnly bool `json:"observe_only"`
	// DispatchedRing and DispatchRound describe the live dispatch state:
	// which ring currently holds jobs and how many rounds have been sent.
	DispatchedRing string `json:"dispatched_ring,omitempty"`
	DispatchRound  int    `json:"dispatch_round,omitempty"`
	Guidance       string `json:"guidance"`
}

const upgradeGuidance = "A staged rollout halts AUTOMATICALLY when a ring fails: one unhealthy " +
	"agent is enough, and so is silence — an agent that took an upgrade and stopped answering is " +
	"the most likely shape of a bad build, so it is never scored as a success. Resuming restarts " +
	"at the ring that halted, not past it; skipping ahead would leave the agents whose failure " +
	"stopped the rollout on the broken build while the campaign reported success. Pause gates " +
	"dispatch, not just the button. An empty ring halts too: an unassigned canary proves nothing, " +
	"and advancing through it would skip the stage whose failure is supposed to stop the rollout."

func (a *API) getUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out := upgradeCampaignResponse{Guidance: upgradeGuidance,
		Rings: map[string]int{}, Versions: map[string]int{}}
	if rings, err := a.store.AgentRingCounts(r.Context(), tenantID); err == nil {
		out.Rings = rings
	}
	if versions, err := a.store.AgentVersionHistogram(r.Context(), tenantID); err == nil {
		out.Versions = versions
	}
	c, active, err := a.store.ActiveAgentUpgradeCampaign(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if active {
		out.Active = true
		out.ID, out.TargetVersion, out.Status = c.ID, c.TargetVersion, c.Status
		out.CurrentRing, out.HaltedAtRing, out.Reason = c.CurrentRing, c.HaltedAtRing, c.Reason
		out.ObserveOnly = len(c.ArtifactsJSON) == 0
		out.DispatchedRing, out.DispatchRound = c.DispatchedRing, c.DispatchRound
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) openUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	idem := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idem, func(ctx context.Context, tenantID string) (int, any, error) {
		var body upgradeCampaignBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := fleet.ValidateArtifacts(body.Artifacts); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		c, err := a.orch.OpenAgentUpgradeCampaign(ctx, tenantID, body.TargetVersion, principalSubject(ctx), body.Artifacts)
		if err != nil {
			var active *orchestrator.AgentUpgradeCampaignActiveError
			if errors.As(err, &active) {
				return 0, nil, errStatus(http.StatusConflict, fmt.Sprintf("a campaign is already active for this tenant (id %s, target %s); finish, halt, or cancel it before starting another", active.ActiveID, active.TargetVersion))
			}
			return 0, nil, err
		}
		return http.StatusCreated, upgradeCampaignResponse{
			ID: c.ID, TargetVersion: c.TargetVersion, Active: true, Status: c.Status,
			ObserveOnly: len(body.Artifacts) == 0,
			Rings:       map[string]int{}, Versions: map[string]int{}, Guidance: upgradeGuidance,
		}, nil
	})
}

// campaignControl handles pause and resume through one constructor, so the
// state rules cannot be enforced on one verb and forgotten on the other.
func (a *API) campaignControl(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idem := r.Header.Get("Idempotency-Key")
		a.mutate(w, r, idem, func(ctx context.Context, tenantID string) (int, any, error) {
			c, active, err := a.store.ActiveAgentUpgradeCampaign(ctx, tenantID)
			if err != nil {
				return 0, nil, err
			}
			if !active {
				return 0, nil, errStatus(http.StatusNotFound, "no active upgrade campaign")
			}
			var d fleet.Decision
			switch action {
			case "pause":
				d = fleet.Decision{NextState: fleet.StatePaused, NextRing: fleet.Ring(c.CurrentRing),
					Reason: "Paused by " + principalSubject(ctx) + "."}
			case "resume":
				at := fleet.Ring(c.HaltedAtRing)
				if at == "" {
					at = fleet.Ring(c.CurrentRing)
				}
				d, err = fleet.Resume(c.Status, at)
				if err != nil {
					return 0, nil, errStatus(http.StatusConflict, err.Error())
				}
			}
			if err := a.orch.AdvanceAgentUpgradeCampaign(ctx, tenantID, c.ID, d, ""); err != nil {
				return 0, nil, err
			}
			return http.StatusOK, upgradeCampaignResponse{
				ID: c.ID, TargetVersion: c.TargetVersion, Active: true, Status: d.NextState,
				CurrentRing: string(d.NextRing), HaltedAtRing: c.HaltedAtRing, Reason: d.Reason,
				Rings: map[string]int{}, Versions: map[string]int{}, Guidance: upgradeGuidance,
			}, nil
		})
	}
}

func (a *API) assignAgentRing(w http.ResponseWriter, r *http.Request) {
	idem := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idem, func(ctx context.Context, tenantID string) (int, any, error) {
		var body ringAssignBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(body.AgentID) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "agent_id is required")
		}
		if err := a.orch.AssignAgentUpgradeRing(ctx, tenantID, body.AgentID, strings.TrimSpace(body.Ring)); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]string{"agent_id": body.AgentID, "ring": body.Ring}, nil
	})
}
