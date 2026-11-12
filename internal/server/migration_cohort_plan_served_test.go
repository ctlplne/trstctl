// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// P3-L1: a read-only planner builds canary-first cohorts from a selector
// (profile, owner or connector here; issuer in P3's served test) instead of
// an operator listing every member. Members are deployed X.509 identities
// bound to an enabled deployment target, placed in name order with their
// target's host agent; the others the selector matched are listed as
// skipped with the reason. The plan feeds the assessment unchanged.
func TestServedMigrationCohortPlanP3L1(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})
	agentID := agentRowID(h.tenant, h.agent)
	target := func(name, kind string, enabled bool) store.DeploymentTarget {
		t.Helper()
		config, err := json.Marshal(map[string]any{
			"executor": "agent", "cert_path": "/etc/p3l1/" + name + ".crt", "key_path": "/etc/p3l1/" + name + ".key",
			"required_agent_id": agentID, "required_agent_role": mtls.AgentRoleHost,
			"verify_address": "127.0.0.1:9", "verify_server_name": name + ".p3l1.test",
		})
		if err != nil {
			t.Fatal(err)
		}
		out, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "host/p3l1-" + name, Type: kind, Config: config, Enabled: enabled, EnabledSet: true})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	nginx, haproxy, disabled := target("nginx", "nginx", true), target("haproxy", "haproxy", true), target("off", "nginx", false)
	web, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "P3-L1 web team", "")
	if err != nil {
		t.Fatal(err)
	}
	api, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "P3-L1 api team", "")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	identity := func(n int, name string, owner store.Owner, profile string, at store.DeploymentTarget, deployed bool) {
		t.Helper()
		attrs, err := json.Marshal(map[string]string{"deployment_target_id": at.ID, "connector": at.Type, "target": at.Name, "profile_name": profile})
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("40400000-0000-4000-8000-0000000031%02d", n)
		if _, err := h.srv.orch.EnsureIdentity(ctx, h.tenant, id, store.Identity{
			Kind: store.KindX509Certificate, Name: name, OwnerID: owner.ID, Attributes: attrs,
		}); err != nil {
			t.Fatal(err)
		}
		if deployed {
			for _, state := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed} {
				if err := h.srv.orch.Transition(ctx, h.tenant, id, state, "p3l1 fixture"); err != nil {
					t.Fatalf("%s → %s: %v", name, state, err)
				}
			}
		}
		ids[name] = id
	}
	identity(1, "web-c.p3l1.test", web, "p3l1-web", nginx, true)
	identity(2, "web-a.p3l1.test", web, "p3l1-web", nginx, true)
	identity(3, "web-d.p3l1.test", web, "p3l1-web", haproxy, true)
	identity(4, "web-b.p3l1.test", web, "p3l1-web", nginx, true)
	identity(5, "web-e.p3l1.test", web, "p3l1-web", nginx, false)   // matched, not deployed
	identity(6, "web-f.p3l1.test", web, "p3l1-web", disabled, true) // matched, its target is disabled
	identity(7, "api-a.p3l1.test", api, "p3l1-api", nginx, true)

	reader := seedScopedTokenSubject(t, h.store, h.tenant, "p3l1-planner", "graph:read")
	plan := func(query url.Values, wantStatus int) migrationCohortPlanView {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/migrations/cohort-plan?"+query.Encode(), reader, "", nil)
		var out migrationCohortPlanView
		if status != wantStatus || (status == http.StatusOK && json.Unmarshal(body, &out) != nil) {
			t.Fatalf("plan %s: HTTP %d %s", query.Encode(), status, body)
		}
		return out
	}
	cohorts := func(p migrationCohortPlanView) string {
		var parts []string
		for _, wave := range p.Waves {
			var names []string
			for _, m := range wave.Members {
				names = append(names, strings.TrimSuffix(m.Name, ".p3l1.test"))
				if m.AgentID != agentID || m.IdentityID != ids[m.Name] {
					t.Fatalf("member %+v, want identity %s on agent %s", m, ids[m.Name], agentID)
				}
			}
			parts = append(parts, wave.ID+":"+strings.Join(names, ","))
		}
		return strings.Join(parts, " ")
	}

	byProfile := plan(url.Values{"profile": {"p3l1-web"}, "canary_size": {"1"}, "cohort_size": {"2"}}, http.StatusOK)
	if got := cohorts(byProfile); got != "canary:web-a cohort-2:web-b,web-c cohort-3:web-d" || byProfile.Members != 4 || byProfile.Truncated {
		t.Fatalf("by profile: %s (%d members, truncated %v)", got, byProfile.Members, byProfile.Truncated)
	}
	var skipped []string
	for _, s := range byProfile.Skipped {
		skipped = append(skipped, strings.TrimSuffix(s.Name, ".p3l1.test")+"="+s.Reason)
	}
	if strings.Join(skipped, " | ") != "web-e=not deployed (requested) | web-f=no enabled deployment target" || byProfile.SkippedCount != 2 {
		t.Fatalf("skipped: %v (%d)", skipped, byProfile.SkippedCount)
	}
	if got := cohorts(plan(url.Values{"profile": {"p3l1-web"}, "connector": {"haproxy"}}, http.StatusOK)); got != "canary:web-d" {
		t.Fatalf("by profile and connector: %s", got)
	}
	if got := cohorts(plan(url.Values{"owner_id": {api.ID}}, http.StatusOK)); got != "canary:api-a" {
		t.Fatalf("by owner: %s", got)
	}
	defaults := plan(url.Values{"profile": {"p3l1-web"}}, http.StatusOK)
	if got := cohorts(defaults); got != "canary:web-a cohort-2:web-b,web-c,web-d" || defaults.CanarySize != migration.DefaultCanarySize || defaults.CohortSize != migration.DefaultCohortSize {
		t.Fatalf("default sizes: %s (%d/%d)", got, defaults.CanarySize, defaults.CohortSize)
	}
	plan(url.Values{}, http.StatusBadRequest)
	plan(url.Values{"profile": {"p3l1-web"}, "canary_size": {"11"}}, http.StatusBadRequest)
	plan(url.Values{"owner_id": {"not-a-uuid"}}, http.StatusBadRequest)

	// The plan feeds the assessment as it stands.
	var waves []any
	for _, wave := range byProfile.Waves {
		var members []any
		for _, m := range wave.Members {
			members = append(members, m.IdentityID)
		}
		waves = append(waves, map[string]any{"id": wave.ID, "ordinal": wave.Ordinal, "members": members})
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/assess", reader, "p3l1-assess",
		map[string]any{"plan_id": "p3l1", "require_full_trust": true, "waves": waves})
	var assessed migration.Assessment
	if status != http.StatusOK || json.Unmarshal(body, &assessed) != nil || assessed.Members != 4 || len(assessed.Waves) != 3 {
		t.Fatalf("assess the planned cohorts: HTTP %d %s", status, body)
	}
}

// migrationCohortPlanView reads GET /api/v1/migrations/cohort-plan.
type migrationCohortPlanView struct {
	CanarySize int                       `json:"canary_size"`
	CohortSize int                       `json:"cohort_size"`
	Members    int                       `json:"members"`
	Truncated  bool                      `json:"truncated"`
	Waves      []migration.PlannedCohort `json:"waves"`
	Skipped    []struct {
		IdentityID string `json:"identity_id"`
		Name       string `json:"name"`
		Reason     string `json:"reason"`
	} `json:"skipped"`
	SkippedCount int `json:"skipped_count"`
}
