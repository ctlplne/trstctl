// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A66 + A67: a per-agent claim quota caps how many leases one agent may hold
// at once, independent of the shared bulkhead, and the Agents API attributes
// each live claim to the agent holding it with the quota beside it. A lease
// that closes frees a slot.
func TestServedPerAgentClaimQuotaWithholdsWorkAndAgentsAttributeLiveClaims(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"revocation.probe"}, func(d *Deps) {
		d.AgentMaxLiveClaimsPerAgent = 2
	})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "relay-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	for i, key := range []string{"a66-probe-1", "a66-probe-2", "a66-probe-3"} {
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
				TenantID: h.tenant, Destination: "revocation.probe", IdempotencyKey: key,
				Payload: []byte(`{"probe":"` + key + `"}`), RequiredAgentRole: mtls.AgentRoleNetwork,
			})
			return err
		}); err != nil {
			t.Fatalf("enqueue probe %d: %v", i, err)
		}
	}
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read")
	readAgent := func() map[string]any {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/agents", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("list agents: status %d body %s", status, body)
		}
		var response struct {
			Agents []map[string]any `json:"agents"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("decode agents: %v (%s)", err, body)
		}
		for _, agent := range response.Agents {
			if agent["name"] == h.agent {
				return agent
			}
		}
		t.Fatalf("agent %q is not in the fleet: %s", h.agent, body)
		return nil
	}
	claim := func(limit int) []transport.ClaimedJob {
		t.Helper()
		out, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"revocation.probe"}, Limit: limit, LeaseSeconds: 120})
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		return out.Jobs
	}

	// Before any claim the agent holds nothing and the quota is served.
	agent := readAgent()
	if claims, _ := agent["live_claims"].([]any); len(claims) != 0 || agent["claim_quota"] != float64(2) || agent["claim_quota_reached"] != false {
		t.Fatalf("idle agent = claims %v quota %v reached %v", agent["live_claims"], agent["claim_quota"], agent["claim_quota_reached"])
	}

	// Three rows wait; the quota hands out two and withholds the third.
	first := claim(5)
	if len(first) != 2 {
		t.Fatalf("claimed %d jobs under a quota of 2, want 2", len(first))
	}
	if again := claim(5); len(again) != 0 {
		t.Fatalf("an agent at quota claimed %d more jobs, want none", len(again))
	}
	agent = readAgent()
	claims, _ := agent["live_claims"].([]any)
	if len(claims) != 2 || agent["claim_quota_reached"] != true {
		t.Fatalf("agent at quota = claims %v reached %v", agent["live_claims"], agent["claim_quota_reached"])
	}
	byJob := map[float64]map[string]any{}
	for _, item := range claims {
		entry := item.(map[string]any)
		byJob[entry["job_id"].(float64)] = entry
	}
	for _, job := range first {
		entry, ok := byJob[float64(job.JobID)]
		if !ok || entry["kind"] != "revocation.probe" || entry["attempt"] != float64(job.Attempt) || entry["lease_expires_at"] == nil {
			t.Fatalf("live claim for job %d = %v", job.JobID, entry)
		}
	}

	// Closing one lease frees one slot: the withheld row is handed out.
	if _, err := h.client.ReportJobResult(ctx, h.report(t, first[0].JobID, first[0].Attempt, transport.JobOutcomeFailed, "a66: released for the quota proof", "")); err != nil {
		t.Fatalf("report: %v", err)
	}
	third := claim(5)
	if len(third) != 1 || third[0].JobID == first[0].JobID || third[0].JobID == first[1].JobID {
		t.Fatalf("after one lease closed the agent claimed %+v, want exactly the withheld row", third)
	}
	agent = readAgent()
	if claims, _ := agent["live_claims"].([]any); len(claims) != 2 || agent["claim_quota_reached"] != true {
		t.Fatalf("agent after refill = claims %v reached %v", agent["live_claims"], agent["claim_quota_reached"])
	}
}
