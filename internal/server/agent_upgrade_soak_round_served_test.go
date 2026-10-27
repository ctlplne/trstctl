// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Recording a soak changes only the campaign's reason. A dispatching campaign
// keeps its dispatch round while it soaks, so no second round of upgrade jobs
// goes out to agents already on the target build; an observe-only campaign
// keeps its soak start, the moment it entered the ring, so the window ends
// when it said it would and later sweeps inside it change nothing.
func TestServedUpgradeSoakKeepsTheDispatchRoundAndTheSoakStart(t *testing.T) {
	t.Run("dispatching", func(t *testing.T) {
		ctx := context.Background()
		h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{"agent.upgrade"})
		if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "1.0.0", Status: "active"}); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/upgrade-ring", tok,
			"soak-round-ring", map[string]any{"agent_id": agentRowID(h.tenant, h.agent), "ring": "canary"}); status != http.StatusOK {
			t.Fatalf("assign ring: %d %s", status, body)
		}
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
			"soak-round-campaign", map[string]any{
				"target_version": "2.0.0", "soak_seconds": 3600,
				"artifacts": []map[string]any{{"os": "linux", "arch": "amd64", "url": "https://dl.example/agent-2.0.0", "sha256": strings.Repeat("ab", 32)}},
			}); status != http.StatusCreated {
			t.Fatalf("open campaign: %d %s", status, body)
		}
		sweep := func() {
			t.Helper()
			if err := h.srv.RunAgentUpgradeCampaignOnce(ctx, h.tenant); err != nil {
				t.Fatal(err)
			}
		}
		claim := func(kind string) []transport.ClaimedJob {
			t.Helper()
			claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{kind}, Limit: 4, LeaseSeconds: 120})
			if err != nil {
				t.Fatalf("claim %s: %v", kind, err)
			}
			return claimed.Jobs
		}

		sweep()
		upgrades := claim("agent.upgrade")
		if len(upgrades) != 1 {
			t.Fatalf("upgrade jobs after the first sweep = %d, want 1", len(upgrades))
		}
		if _, err := h.client.ReportJobResult(ctx, h.report(t, upgrades[0].JobID, upgrades[0].Attempt, transport.JobOutcomeExecuted, "staged 2.0.0; restarting to load it", "")); err != nil {
			t.Fatalf("report upgrade: %v", err)
		}
		if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "2.0.0", Status: "active"}); err != nil {
			t.Fatalf("heartbeat on the target build: %v", err)
		}
		sweep()
		checks := claim(relay.KindAgentSelfCheck)
		if len(checks) != 1 {
			t.Fatalf("self-checks = %d, want 1", len(checks))
		}
		passed, _ := json.Marshal(relay.SelfCheckReport{Version: "2.0.0", Checks: []relay.SelfCheckResult{
			{Name: "version", OK: true, Detail: "running 2.0.0"},
			{Name: "job_channel", OK: true},
		}})
		if _, err := h.client.ReportJobResult(ctx, h.report(t, checks[0].JobID, checks[0].Attempt, transport.JobOutcomeExecuted, string(passed), "")); err != nil {
			t.Fatalf("report self-check: %v", err)
		}
		sweep()
		view := readCampaign(t, h.servedHarness, tok)
		if view.Status != fleet.StateRunning || view.CurrentRing != "canary" || !strings.HasPrefix(view.Reason, "Soaking: the canary ring verified") {
			t.Fatalf("after verification inside the soak = %+v; want running at canary, soaking", view)
		}
		c, _, err := h.store.ActiveAgentUpgradeCampaign(ctx, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if c.DispatchRound != 1 || c.DispatchedRing != "canary" {
			t.Fatalf("recording the soak changed the dispatch: round %d, dispatched ring %q; want round 1 still dispatched to canary", c.DispatchRound, c.DispatchedRing)
		}
		sweep()
		if again := claim("agent.upgrade"); len(again) != 0 {
			t.Fatalf("a sweep inside the soak sent %d more upgrade jobs to an agent already on the target build", len(again))
		}
		if again := readCampaign(t, h.servedHarness, tok); again.Reason != view.Reason || again.CurrentRing != "canary" {
			t.Fatalf("a sweep inside the soak changed the campaign: %+v", again)
		}
	})

	t.Run("observe-only", func(t *testing.T) {
		h := newOperatingServedHarness(t, config.Protocols{})
		tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
		canary := seedAgent(t, h, "soak-start-canary", "1.0.0")
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-ring", tok, "soak-start-ring", map[string]any{"agent_id": canary.ID, "ring": "canary"}); status != http.StatusOK {
			t.Fatalf("assign ring: %d %s", status, body)
		}
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok, "soak-start-campaign", map[string]any{"target_version": "2.0.0", "soak_seconds": 3600}); status != http.StatusCreated {
			t.Fatalf("open campaign: %d %s", status, body)
		}
		seen := time.Now().UTC()
		upgraded := canary
		upgraded.Version, upgraded.LastSeenAt = "2.0.0", &seen
		if err := h.store.UpsertAgent(t.Context(), upgraded); err != nil {
			t.Fatal(err)
		}
		if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
			t.Fatal(err)
		}
		passSelfChecks(t, h)
		// The campaign entered the canary ring ten minutes ago.
		opened, _, err := h.store.ActiveAgentUpgradeCampaign(t.Context(), h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE agent_upgrade_campaigns SET updated_at = now() - interval '10 minutes' WHERE tenant_id=$1 AND id=$2`, h.tenant, opened.ID); err != nil {
			t.Fatal(err)
		}
		entered, _, err := h.store.ActiveAgentUpgradeCampaign(t.Context(), h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
			t.Fatal(err)
		}
		view := readCampaign(t, h, tok)
		if want := fleet.SoakReason("canary", entered.UpdatedAt.Add(time.Hour)); view.Reason != want {
			t.Fatalf("soak reason = %q; want %q, an hour after the ring was entered", view.Reason, want)
		}
		if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
			t.Fatal(err)
		}
		if again := readCampaign(t, h, tok); again.Reason != view.Reason || again.CurrentRing != "canary" {
			t.Fatalf("a later sweep inside the soak moved the window: %q, was %q", again.Reason, view.Reason)
		}
	})
}
