// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/config"
)

// A70: a campaign opened with a soak window keeps a verified ring under
// observation before the next ring is dispatched; the campaign says so in its
// reason; an agent that goes silent during the soak halts it; once the window
// passes with the ring healthy the rollout moves on. Zero soak keeps the
// immediate advance every earlier campaign had.
func TestServedUpgradeCampaignSoaksAVerifiedRingBeforeTheNextOne(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	canary := seedAgent(t, h, "soak-canary", "1.0.0")
	early := seedAgent(t, h, "soak-early", "1.0.0")
	broad := seedAgent(t, h, "soak-broad", "1.0.0")
	for id, ring := range map[string]string{canary.ID: "canary", early.ID: "early", broad.ID: "broad"} {
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-ring", tok, "soak-ring-"+id, map[string]any{"agent_id": id, "ring": ring}); status != http.StatusOK {
			t.Fatalf("assign ring: %d %s", status, body)
		}
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok, "soak-campaign-bad", map[string]any{"target_version": "2.0.0", "soak_seconds": -1}); status != http.StatusBadRequest {
		t.Fatalf("negative soak: %d %s; want 400", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-campaign", tok, "soak-campaign", map[string]any{"target_version": "2.0.0", "soak_seconds": 3600}); status != http.StatusCreated || !strings.Contains(string(body), `"soak_seconds":3600`) {
		t.Fatalf("open campaign with a soak: %d %s", status, body)
	}

	// The canary comes up on the target build and is heard from: verified, but
	// the window has not passed, so the campaign soaks and says until when.
	seen := time.Now().UTC()
	fixed := canary
	fixed.Version, fixed.LastSeenAt = "2.0.0", &seen
	if err := h.store.UpsertAgent(t.Context(), fixed); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	// A71: the sweep above queued the agent's functional self-check; the
	// agent answers it, and only the next sweep may verify the ring.
	passSelfChecks(t, h)
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	view := readCampaign(t, h, tok)
	if view.Status != fleet.StateRunning || view.CurrentRing != "canary" || !strings.HasPrefix(view.Reason, "Soaking: the canary ring verified") || view.SoakSeconds != 3600 {
		t.Fatalf("after verification inside the soak = status %q ring %q reason %q soak %d; want running at canary, soaking", view.Status, view.CurrentRing, view.Reason, view.SoakSeconds)
	}
	// Another sweep inside the window changes nothing and appends no new reason.
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if again := readCampaign(t, h, tok); again.Reason != view.Reason || again.CurrentRing != "canary" {
		t.Fatalf("a sweep inside the soak changed the campaign: %+v", again)
	}

	// The window passes: the sweep reads the campaign's last change as the
	// soak start, so move that back past the window. The ring stayed healthy,
	// so the rollout advances to the early ring.
	if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE agent_upgrade_campaigns SET updated_at = now() - interval '2 hours' WHERE tenant_id=$1 AND id=$2`, h.tenant, view.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if after := readCampaign(t, h, tok); after.CurrentRing != "early" || after.Status != fleet.StateRunning {
		t.Fatalf("after the soak passed = ring %q status %q reason %q; want the early ring dispatched", after.CurrentRing, after.Status, after.Reason)
	}

	// The early ring verifies, then its agent stops heartbeating inside the
	// soak: silence halts, exactly as it would before the soak.
	fixedEarly := early
	fixedEarly.Version = "2.0.0"
	stale := time.Now().UTC().Add(-2 * time.Hour)
	fixedEarly.LastSeenAt = &stale
	if err := h.store.UpsertAgent(t.Context(), fixedEarly); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	// A71: the sweep above queued the agent's functional self-check; the
	// agent answers it, and only the next sweep may verify the ring.
	passSelfChecks(t, h)
	if err := h.srv.RunAgentUpgradeCampaignOnce(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if halted := readCampaign(t, h, tok); halted.Status != fleet.StateHalted || halted.HaltedAtRing != "early" {
		t.Fatalf("an early-ring agent silent during the soak left the campaign %q at %q; want halted at early", halted.Status, halted.HaltedAtRing)
	}
}
