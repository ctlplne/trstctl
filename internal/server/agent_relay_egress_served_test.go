// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A190-L1: a relay that claims jobs reports the egress policy its job
// connections follow on its heartbeat, and GET /api/v1/agents serves it as
// reported_relay_egress: whether an allowlist is set and what it lists,
// bounded, with a list cut short never read as no allowlist. A relay that
// claims no jobs reports none.
func TestServedAgentsReportTheRelayEgressPolicyA190L1(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork})
	tok := seedScopedToken(t, h.store, h.tenant, "agents:read")

	egress := func() (map[string]any, bool) {
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
				report, ok := agent["reported_relay_egress"].(map[string]any)
				return report, ok
			}
		}
		t.Fatalf("agent %q is not in the fleet: %s", h.agent, body)
		return nil, false
	}
	heartbeat := func(report *transport.RelayEgressReport) {
		t.Helper()
		if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
			AgentID: h.agent, Version: "relay-1.0.0", Status: "active",
			Executors: &transport.ExecutorReport{Version: "relay-1.0.0", RelayEgress: report,
				Kinds: []transport.ExecutorKind{{Kind: "connector.deploy", Connectors: []string{"f5"}}}},
		}); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
	}

	heartbeat(nil)
	if report, ok := egress(); ok {
		t.Fatalf("a relay that claims no jobs is served an egress policy: %v", report)
	}

	heartbeat(&transport.RelayEgressReport{Allow: []string{"10.20.0.0/16", "192.0.2.7", "198.51.100.9:8443"}})
	report, ok := egress()
	if !ok || report["restricted"] != true || !jsonListEquals(report["allow"], []string{"10.20.0.0/16", "192.0.2.7", "198.51.100.9:8443"}) || report["truncated"] != nil {
		t.Fatalf("reported_relay_egress = %v, want the relay's allowlist", report)
	}
	// Event-sourced: the policy rides an agent.heartbeat v8 event.
	recorded := false
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type == projections.EventAgentHeartbeat && e.TenantID == h.tenant && e.SchemaVersion == projections.AgentHeartbeatRelayEgressSchemaVersion {
			recorded = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	if !recorded {
		t.Fatal("the relay egress policy was not recorded on an agent.heartbeat v8 event")
	}

	heartbeat(&transport.RelayEgressReport{Allow: []string{}})
	if report, ok = egress(); !ok || report["restricted"] != false || !jsonListEquals(report["allow"], []string{}) {
		t.Fatalf("reported_relay_egress without an allowlist = %v, want restricted false and an empty list", report)
	}

	// Bounded: at most 64 entries are recorded, and an entry that is not an
	// address, prefix or address:port is dropped; either way the list is
	// marked truncated and the relay is still served as restricted.
	long := []string{"appliance.example.com", strings.Repeat("9", 65)}
	for i := range 70 {
		long = append(long, fmt.Sprintf("10.0.%d.0/24", i))
	}
	heartbeat(&transport.RelayEgressReport{Allow: long})
	report, ok = egress()
	allow, _ := report["allow"].([]any)
	if !ok || report["restricted"] != true || report["truncated"] != true || len(allow) != projections.AgentRelayEgressMaxEntries || allow[0] != "10.0.0.0/24" {
		t.Fatalf("an oversized report = restricted %v truncated %v with %d entries (first %v), want 64 valid entries marked truncated", report["restricted"], report["truncated"], len(allow), allow)
	}
	heartbeat(&transport.RelayEgressReport{Allow: []string{"appliance.example.com"}})
	if report, ok = egress(); !ok || report["restricted"] != true || report["truncated"] != true || !jsonListEquals(report["allow"], []string{}) {
		t.Fatalf("a report with only an unusable entry = %v, want restricted and truncated, never no allowlist", report)
	}
}
