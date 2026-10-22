// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A69: one call places every unassigned, in-service agent in a ring
// deterministically — the fresh, longest-enrolled agent becomes the canary —
// without moving an agent an operator already placed, and a fleet too small
// to fill three rings is refused rather than planned into a halt.
func TestServedAutomaticRingAssignmentPicksTheCanaryAndLeavesManualChoicesAlone(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read", "agents:write")
	now := time.Now().UTC()
	seed := func(name string, enrolled time.Time, seen *time.Time, status string) store.Agent {
		t.Helper()
		a := store.Agent{ID: uuid.NewString(), TenantID: h.tenant, Name: name, Status: status, Version: "1.0.0", CreatedAt: enrolled, LastSeenAt: seen}
		if err := h.store.UpsertAgent(t.Context(), a); err != nil {
			t.Fatal(err)
		}
		// Pin the enrollment time and heartbeat the planner orders by, whatever the
		// upsert defaults them to.
		if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE agents SET created_at=$1, last_seen_at=$2 WHERE tenant_id=$3 AND id=$4`, enrolled, seen, h.tenant, a.ID); err != nil {
			t.Fatal(err)
		}
		return a
	}
	fresh := now.Add(-10 * time.Second)
	stale := now.Add(-2 * time.Hour)
	oldest := seed("oldest-silent", now.Add(-400*time.Hour), &stale, "active")
	veteran := seed("veteran-fresh", now.Add(-300*time.Hour), &fresh, "active")
	middle := seed("middle-fresh", now.Add(-100*time.Hour), &fresh, "active")
	newest := seed("newest-fresh", now.Add(-1*time.Hour), &fresh, "active")
	manual := seed("manual-broad", now.Add(-500*time.Hour), &fresh, "active")
	gone := seed("offboarded", now.Add(-600*time.Hour), &fresh, "offboarded")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-ring", tok, "a69-manual", map[string]any{"agent_id": manual.ID, "ring": "broad"}); status != http.StatusOK {
		t.Fatalf("manual assignment: %d %s", status, body)
	}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-rings/auto-assign", tok, "a69-auto-1", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("auto-assign: %d %s", status, body)
	}
	var placed struct {
		Canary     []struct{ AgentID, Name string } `json:"canary"`
		EarlyCount int                              `json:"early_count"`
		BroadCount int                              `json:"broad_count"`
		Assigned   int                              `json:"assigned"`
		Rule       string                           `json:"rule"`
	}
	if err := json.Unmarshal(body, &placed); err != nil {
		t.Fatal(err)
	}
	if len(placed.Canary) != 1 || placed.Canary[0].Name != veteran.Name || placed.EarlyCount != 1 || placed.BroadCount != 2 || placed.Assigned != 4 || placed.Rule == "" {
		t.Fatalf("placement = %s; want veteran-fresh as the canary, one early, two broad, four assigned, with the rule stated", body)
	}
	ring := func(id string) string {
		t.Helper()
		for _, r := range []string{"canary", "early", "broad", ""} {
			agents, err := h.store.AgentsInRing(t.Context(), h.tenant, r)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range agents {
				if a.ID == id {
					return r
				}
			}
		}
		return "?"
	}
	if ring(veteran.ID) != "canary" || ring(middle.ID) != "early" || ring(newest.ID) != "broad" || ring(oldest.ID) != "broad" {
		t.Fatalf("rings = veteran %s, middle %s, newest %s, oldest-silent %s", ring(veteran.ID), ring(middle.ID), ring(newest.ID), ring(oldest.ID))
	}
	if ring(manual.ID) != "broad" {
		t.Fatalf("the operator's manual placement moved to %s", ring(manual.ID))
	}
	if ring(gone.ID) != "" {
		t.Fatalf("an offboarded agent was placed in %s", ring(gone.ID))
	}

	// Nothing left to place: the fleet is too small for a second plan, and the
	// refusal says so instead of emptying a ring.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-rings/auto-assign", tok, "a69-auto-2", map[string]any{}); status != http.StatusConflict || !strings.Contains(string(body), "fewer than three") {
		t.Fatalf("second auto-assign with nothing unassigned: %d %s; want 409 naming the shortfall", status, body)
	}
	// A canary of two is honoured when the fleet allows it.
	spare1 := seed("spare-1", now.Add(-50*time.Hour), &fresh, "active")
	spare2 := seed("spare-2", now.Add(-40*time.Hour), &fresh, "active")
	spare3 := seed("spare-3", now.Add(-30*time.Hour), &fresh, "active")
	spare4 := seed("spare-4", now.Add(-20*time.Hour), &fresh, "active")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/agents/upgrade-rings/auto-assign", tok, "a69-auto-3", map[string]any{"canary_count": 2, "early_percent": 50}); status != http.StatusOK {
		t.Fatalf("auto-assign with two canaries: %d %s", status, body)
	}
	if ring(spare1.ID) != "canary" || ring(spare2.ID) != "canary" || ring(spare3.ID) != "early" || ring(spare4.ID) != "broad" {
		t.Fatalf("second plan rings = %s %s %s %s", ring(spare1.ID), ring(spare2.ID), ring(spare3.ID), ring(spare4.ID))
	}
}
