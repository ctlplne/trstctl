// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"encoding/json"
	"net/http"
	"strings"
	"testing"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/config"
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
			"A pause that grays out a button while the sweep keeps dispatching is worse than no "+
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

// A5's dispatch half, end to end through the served surface: a campaign with
// artifacts DISPATCHES targeted jobs through the ledger, halts the moment a
// signed receipt reports failure, and re-dispatches a fresh round on resume.
func TestServedDispatchingCampaignDispatchesAndGatesOnReceipts(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")

	canary := seedAgent(t, h, "canary-1", "1.0.0")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-ring", tok,
		"ring-d", map[string]any{"agent_id": canary.ID, "ring": "canary"}); status != http.StatusOK {
		t.Fatalf("assign ring: %d %s", status, body)
	}

	digest := strings.Repeat("ab", 32)
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"campaign-d", map[string]any{
			"target_version": "2.0.0",
			"artifacts": []map[string]any{{
				"os": "linux", "arch": "amd64",
				"url": "https://dl.example/agent-2.0.0", "sha256": digest,
			}},
		}); status != http.StatusCreated {
		t.Fatalf("open campaign: %d %s", status, body)
	}

	// Sweep 1: the canary ring has no dispatch round, so this sweep's job is
	// to create one — not to score anything.
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	type dispatchedRow struct {
		id      int64
		agentID string
		payload []byte
	}
	readJob := func() (dispatchedRow, bool) {
		var row dispatchedRow
		found := false
		if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			err := tx.QueryRow(t.Context(),
				`SELECT id, coalesce(required_agent_id::text, ''), payload FROM outbox
				  WHERE tenant_id = $1 AND destination = 'agent.upgrade'
				  ORDER BY id DESC LIMIT 1`, h.tenant).Scan(&row.id, &row.agentID, &row.payload)
			if err == nil {
				found = true
				return nil
			}
			if err.Error() == pgx.ErrNoRows.Error() {
				return nil
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return row, found
	}
	job, ok := readJob()
	if !ok {
		t.Fatal("the sweep dispatched nothing.\n\n" +
			"This is the epic's whole point: before dispatch existed, the campaign observed a " +
			"version change something else performed. A campaign with artifacts must CREATE the work.")
	}
	if job.agentID != canary.ID {
		t.Fatalf("job targets %q, want the canary %q — an untargeted upgrade row is claimable by "+
			"the wrong machine", job.agentID, canary.ID)
	}
	var intent fleet.UpgradeIntent
	if err := json.Unmarshal(job.payload, &intent); err != nil {
		t.Fatalf("job payload is not an upgrade intent: %v", err)
	}
	if intent.TargetVersion != "2.0.0" || len(intent.Artifacts) != 1 || intent.Artifacts[0].SHA256 != digest {
		t.Fatalf("intent = %+v; the agent verifies against exactly this digest", intent)
	}
	view := readCampaign(t, h, tok)
	if view.Status != fleet.StateRunning || view.CurrentRing != "canary" {
		t.Fatalf("after dispatch: status=%q ring=%q, want running@canary", view.Status, view.CurrentRing)
	}

	// The canary's SIGNED receipt says the upgrade failed. The next sweep must
	// halt — no grace applies to an explicit failure.
	if err := h.store.RecordAgentJobReceipt(t.Context(), h.tenant, store.AgentJobReceipt{
		JobID: job.id, Attempt: 1, Agent: "canary-1", Kind: "agent.upgrade",
		Outcome: "failed", State: "verified",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	view = readCampaign(t, h, tok)
	if view.Status != fleet.StateHalted || view.HaltedAtRing != "canary" {
		t.Fatalf("after a failed receipt: status=%q halted_at=%q, want halted@canary.\n\n"+
			"The receipt is the agent's own signed statement that the build is bad; proceeding "+
			"past it carries the build to the rest of the fleet", view.Status, view.HaltedAtRing)
	}

	// Resume must RE-dispatch the canary: a fresh job, a fresh round. The
	// failed round's receipt must not follow the retry.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign/resume",
		tok, "resume-d", nil); status != http.StatusOK {
		t.Fatalf("resume: %d %s", status, body)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	job2, ok := readJob()
	if !ok || job2.id == job.id {
		t.Fatalf("resume did not produce a fresh job (got %v, prior %v); the fixed agent needs a "+
			"new order, and the old round's failed receipt must stop counting", job2.id, job.id)
	}

	// The agent reports the retry executed and comes back on the target
	// version; the ring verifies and the campaign moves on.
	if err := h.store.RecordAgentJobReceipt(t.Context(), h.tenant, store.AgentJobReceipt{
		JobID: job2.id, Attempt: 1, Agent: "canary-1", Kind: "agent.upgrade",
		Outcome: "executed", State: "verified",
	}); err != nil {
		t.Fatal(err)
	}
	upgraded := canary
	upgraded.Version = "2.0.0"
	if err := h.store.UpsertAgent(t.Context(), upgraded); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	view = readCampaign(t, h, tok)
	if view.Status == fleet.StateHalted || view.CurrentRing == "canary" {
		t.Fatalf("after the retry verified: status=%q ring=%q; the campaign must advance past "+
			"canary", view.Status, view.CurrentRing)
	}
}

// A dispatched agent that neither fails nor arrives is SILENT once its grace
// expires, and silence halts.
func TestServedDispatchedSilenceHaltsAfterGrace(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	a := seedAgent(t, h, "canary-quiet", "1.0.0")
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-ring", tok,
		"ring-q", map[string]any{"agent_id": a.ID, "ring": "canary"}); status != http.StatusOK {
		t.Fatal("assign ring failed")
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"campaign-q", map[string]any{
			"target_version": "2.0.0",
			"artifacts": []map[string]any{{
				"os": "linux", "arch": "amd64",
				"url": "https://dl.example/agent", "sha256": strings.Repeat("cd", 32),
			}},
		}); status != http.StatusCreated {
		t.Fatal("open campaign failed")
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	// Inside the grace nothing is decided.
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if view := readCampaign(t, h, tok); view.Status != fleet.StateRunning {
		t.Fatalf("status = %q inside the grace window, want running — a slow download is not a "+
			"verdict", view.Status)
	}
	// Age the dispatch past the grace; the agent never reported and never
	// arrived on the target version.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(),
			`UPDATE agent_upgrade_dispatches SET dispatched_at = dispatched_at - interval '30 minutes'
			  WHERE tenant_id = $1`, h.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	view := readCampaign(t, h, tok)
	if view.Status != fleet.StateHalted {
		t.Fatalf("status = %q after the grace expired with no receipt and no version change, want "+
			"halted.\n\nAn agent that took an upgrade order and went quiet is the most likely shape "+
			"of a bad build", view.Status)
	}
	if !strings.Contains(view.Reason, "never reported") {
		t.Fatalf("halt reason %q does not say the agents were silent", view.Reason)
	}
}
