// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// A71: coming back on the target build is no longer the whole of
// verification. The first sweep that sees the upgraded agent queues it a
// functional self-check pinned to it; the agent claims it over the channel it
// upgraded, answers with a signed receipt, and the ring verifies only once
// that receipt passed. A failed check halts the ring with its own reason; the
// campaign view tallies the round's checks.
func TestServedUpgradeVerificationRequiresTheAgentsFunctionalSelfCheck(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{"agent.upgrade"})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "1.0.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	agentID := agentRowID(h.tenant, h.agent)
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/upgrade-ring", tok,
		"ring-a71", map[string]any{"agent_id": agentID, "ring": "canary"}); status != http.StatusOK {
		t.Fatalf("assign ring: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok,
		"campaign-a71", map[string]any{
			"target_version": "2.0.0",
			"artifacts":      []map[string]any{{"os": "linux", "arch": "amd64", "url": "https://dl.example/agent-2.0.0", "sha256": strings.Repeat("ab", 32)}},
		}); status != http.StatusCreated {
		t.Fatalf("open campaign: %d %s", status, body)
	}
	sweep := func() {
		t.Helper()
		if err := h.srv.RunAgentUpgradeCampaignOnce(ctx, h.tenant); err != nil {
			t.Fatal(err)
		}
	}
	claimOne := func(kind string) transport.ClaimedJob {
		t.Helper()
		claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{kind}, Limit: 4, LeaseSeconds: 120})
		if err != nil || len(claimed.Jobs) != 1 {
			t.Fatalf("claim %s: jobs=%d err=%v", kind, len(claimed.Jobs), err)
		}
		return claimed.Jobs[0]
	}
	selfCheckRows := func() int {
		t.Helper()
		var n int
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, store.AgentSelfCheckDestination).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Sweep 1 dispatches the upgrade; the agent takes it and comes back on
	// the target build. No self-check exists yet.
	sweep()
	upgrade := claimOne("agent.upgrade")
	if _, err := h.client.ReportJobResult(ctx, h.report(t, upgrade.JobID, upgrade.Attempt, transport.JobOutcomeExecuted, "staged 2.0.0; restarting to load it", "")); err != nil {
		t.Fatalf("report upgrade: %v", err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "2.0.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat on the target build: %v", err)
	}
	if selfCheckRows() != 0 {
		t.Fatal("a self-check was queued before the agent was seen on the target build")
	}

	// Sweep 2 sees the target build: it queues the self-check pinned to this
	// agent and does NOT verify the ring yet.
	sweep()
	view := readCampaign(t, h.servedHarness, tok)
	if view.Status != fleet.StateRunning || view.CurrentRing != "canary" {
		t.Fatalf("after the version report alone: status=%q ring=%q; running the target build is not verification", view.Status, view.CurrentRing)
	}
	if view.FunctionalChecks == nil || view.FunctionalChecks.Pending != 1 || view.FunctionalChecks.Passed != 0 {
		t.Fatalf("campaign view checks = %+v, want one pending", view.FunctionalChecks)
	}
	check := claimOne(relay.KindAgentSelfCheck)
	var intent relay.SelfCheckIntent
	if err := json.Unmarshal(check.Payload, &intent); err != nil || intent.TargetVersion != "2.0.0" || intent.CampaignID == "" {
		t.Fatalf("self-check intent = %+v %v", intent, err)
	}

	// The agent's signed receipt says a check failed: the ring halts with a
	// reason that names the functional check, not silence or health.
	failed, _ := json.Marshal(relay.SelfCheckReport{Version: "2.0.0", Checks: []relay.SelfCheckResult{
		{Name: "version", OK: true, Detail: "running 2.0.0"},
		{Name: "host_exec_profile", OK: false, Detail: "allowed root /srv/tls is not a directory"},
	}})
	if _, err := h.client.ReportJobResult(ctx, h.report(t, check.JobID, check.Attempt, transport.JobOutcomeFailed, string(failed), "")); err != nil {
		t.Fatalf("report failed self-check: %v", err)
	}
	sweep()
	view = readCampaign(t, h.servedHarness, tok)
	if view.Status != fleet.StateHalted || view.HaltedAtRing != "canary" || !strings.Contains(view.Reason, "failed the functional self-check") {
		t.Fatalf("after a failed self-check: status=%q halted_at=%q reason=%q", view.Status, view.HaltedAtRing, view.Reason)
	}
	if view.FunctionalChecks == nil || view.FunctionalChecks.Failed != 1 {
		t.Fatalf("campaign view checks after the failure = %+v", view.FunctionalChecks)
	}

	// Resume: a fresh round re-dispatches the upgrade; the agent is already
	// on the target build, so the next sweep asks for a fresh self-check, and
	// the old round's answer stops counting. This time it passes, and the
	// ring verifies.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/upgrade-campaign/resume", tok, "resume-a71", nil); status != http.StatusOK {
		t.Fatalf("resume: %d %s", status, body)
	}
	sweep()
	upgrade = claimOne("agent.upgrade")
	if _, err := h.client.ReportJobResult(ctx, h.report(t, upgrade.JobID, upgrade.Attempt, transport.JobOutcomeExecuted, "already on the target version", "")); err != nil {
		t.Fatalf("report second upgrade: %v", err)
	}
	sweep()
	if selfCheckRows() != 2 {
		t.Fatalf("self-check rows = %d, want a fresh one for the new round", selfCheckRows())
	}
	check = claimOne(relay.KindAgentSelfCheck)
	passed, _ := json.Marshal(relay.SelfCheckReport{Version: "2.0.0", Checks: []relay.SelfCheckResult{
		{Name: "version", OK: true, Detail: "running 2.0.0"},
		{Name: "host_exec_profile", OK: true, Detail: "1 allowed root(s) and 1 action(s) resolve on this host"},
		{Name: "job_channel", OK: true},
	}})
	if _, err := h.client.ReportJobResult(ctx, h.report(t, check.JobID, check.Attempt, transport.JobOutcomeExecuted, string(passed), "")); err != nil {
		t.Fatalf("report passed self-check: %v", err)
	}
	sweep()
	view = readCampaign(t, h.servedHarness, tok)
	if view.Status == fleet.StateHalted && view.HaltedAtRing == "canary" {
		t.Fatalf("after the passed self-check the canary ring did not verify: status=%q reason=%q", view.Status, view.Reason)
	}
	if view.CurrentRing == "canary" && view.Status == fleet.StateRunning {
		t.Fatalf("the campaign stayed on the canary ring after a passed check: %+v", view)
	}
}
