// SPDX-License-Identifier: MPL-2.0

package server

import (
	"github.com/google/uuid"

	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/fleet"
	"trstctl.com/trstctl/internal/store"
)

// A5's acceptance, end to end through the running binary: a staged upgrade
// halts automatically when the canary ring fails, and is resumable after a fix.

type campaignView struct {
	ID           string         `json:"id"`
	Active       bool           `json:"active"`
	Status       string         `json:"status"`
	CurrentRing  string         `json:"current_ring"`
	HaltedAtRing string         `json:"halted_at_ring"`
	Reason       string         `json:"reason"`
	Rings        map[string]int `json:"rings"`
	Versions     map[string]int `json:"versions"`
}

func readCampaign(t *testing.T, h *servedHarness, tok string) campaignView {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/agents/upgrade-campaign", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read campaign: %d %s", status, body)
	}
	var out campaignView
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func seedAgent(t *testing.T, h *servedHarness, name, version string) store.Agent {
	t.Helper()
	a := store.Agent{TenantID: h.tenant, Name: name, Status: "active", Version: version}
	a.ID = uuid.NewString()
	if err := h.store.UpsertAgent(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestServedStagedUpgradeHaltsOnCanaryFailureAndResumesThere(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")

	canary := seedAgent(t, h, "canary-1", "1.0.0")
	broad := seedAgent(t, h, "broad-1", "1.0.0")
	for id, ring := range map[string]string{canary.ID: "canary", broad.ID: "broad"} {
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-ring", tok,
			"ring-"+id, map[string]any{"agent_id": id, "ring": ring}); status != http.StatusOK {
			t.Fatalf("assign ring: %d %s", status, body)
		}
	}

	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"campaign-1", map[string]any{"target_version": "2.0.0"}); status != http.StatusCreated {
		t.Fatalf("open campaign: %d %s", status, body)
	}

	// The canary never comes back on the new version and has not been seen
	// recently: silence. The sweep must halt rather than proceed to broad.
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	view := readCampaign(t, h, tok)
	if view.Status != fleet.StateHalted {
		t.Fatalf("status = %q after a silent canary, want halted.\n\n"+
			"An agent that took an upgrade and stopped answering is the most likely shape of a "+
			"bad build. Proceeding would carry it to the broad ring.", view.Status)
	}
	if view.HaltedAtRing != "canary" {
		t.Fatalf("halted_at_ring = %q, want canary — a resume has to know where to restart",
			view.HaltedAtRing)
	}
	if view.Reason == "" {
		t.Error("the halt carries no reason; \"halted\" alone sends an operator to read logs")
	}

	// A halted campaign must not advance on a later sweep.
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if again := readCampaign(t, h, tok); again.Status != fleet.StateHalted {
		t.Fatalf("a halted campaign advanced to %q on a later sweep. The value of an automatic "+
			"halt is that it does not un-halt itself", again.Status)
	}

	// Fix the canary, then resume: it must restart at canary, not at broad.
	fixed := canary
	fixed.Version = "2.0.0"
	if err := h.store.UpsertAgent(t.Context(), fixed); err != nil {
		t.Fatal(err)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign/resume",
		tok, "resume-1", nil); status != http.StatusOK {
		t.Fatalf("resume: %d %s", status, body)
	}
	resumed := readCampaign(t, h, tok)
	if resumed.CurrentRing != "canary" {
		t.Fatalf("resumed at %q, want canary.\n\n"+
			"Skipping past the ring that halted leaves the agents whose failure stopped the "+
			"rollout on the broken build, while the campaign reports success.", resumed.CurrentRing)
	}
	if resumed.Status != fleet.StateRunning {
		t.Fatalf("status = %q after resume, want running", resumed.Status)
	}

	// Now the canary verifies and the rollout moves on.
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if after := readCampaign(t, h, tok); after.CurrentRing == "canary" && after.Status == fleet.StateHalted {
		t.Fatal("the campaign halted again after the canary was fixed")
	}
}

// A pause must stop dispatch, not merely change a label.
func TestServedPauseActuallyGatesTheSweep(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	a := seedAgent(t, h, "canary-1", "1.0.0")
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-ring", tok,
		"ring-p", map[string]any{"agent_id": a.ID, "ring": "canary"}); status != http.StatusOK {
		t.Fatal("assign ring failed")
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"campaign-p", map[string]any{"target_version": "2.0.0"}); status != http.StatusCreated {
		t.Fatal("open campaign failed")
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign/pause",
		tok, "pause-1", nil); status != http.StatusOK {
		t.Fatalf("pause: %d %s", status, body)
	}
	// A sweep while paused must change nothing.
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if view := readCampaign(t, h, tok); view.Status != fleet.StatePaused {
		t.Fatalf("status = %q after a sweep while paused, want paused.\n\n"+
			"A pause that greys out a button while the sweep keeps dispatching is worse than no "+
			"pause: the operator believes they stopped the rollout.", view.Status)
	}
}

// An unassigned fleet must not let a rollout skip its canary.
func TestServedAnEmptyCanaryRingHaltsRatherThanBeingSkipped(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	seedAgent(t, h, "unassigned-1", "1.0.0")
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"campaign-e", map[string]any{"target_version": "2.0.0"}); status != http.StatusCreated {
		t.Fatal("open campaign failed")
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	view := readCampaign(t, h, tok)
	if view.Status != fleet.StateHalted {
		t.Fatalf("status = %q with an empty canary ring, want halted.\n\n"+
			"An empty ring proves nothing. Advancing through it skips the stage whose failure is "+
			"supposed to stop the rollout — on exactly the fleet nobody has triaged.", view.Status)
	}
	if view.Rings["unassigned"] != 1 {
		t.Errorf("rings = %v; unassigned must be counted and never folded into broad", view.Rings)
	}
}
