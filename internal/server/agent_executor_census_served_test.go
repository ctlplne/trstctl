// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A62: the Agents console used to show only what THIS server build would
// execute for the agent's certificate roles. Now the enrolled binary reports
// its own executor census on its heartbeat and the API serves it beside the
// server census, role-filtered the same way, saying which source describes the
// agent; an older agent that reports nothing shows the server census alone.
func TestServedAgentsReportTheEnrolledBinaryExecutorCensus(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork})
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

	// An agent that reports nothing is described by the server census only.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "old-build", Status: "active"}); err != nil {
		t.Fatalf("plain heartbeat: %v", err)
	}
	agent := readAgent()
	if agent["capability_source"] != "server_census" || agent["reported_capabilities"] != nil || agent["reported_host_tls_probe"] != nil {
		t.Fatalf("agent without a report = source %v reported %v probe %v, want server_census, no reported list and no probe answer", agent["capability_source"], agent["reported_capabilities"], agent["reported_host_tls_probe"])
	}

	// The binary's own census: a network relay started without --relay-claim,
	// carrying an appliance family this server build does not ship under
	// connector.deploy, plus a host-only kind its certificate role filters out.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "relay-0.9.1", Status: "active",
		Executors: &transport.ExecutorReport{Version: "relay-0.9.1", HostTLSProbe: true, Kinds: []transport.ExecutorKind{
			{Kind: "connector.deploy", Connectors: []string{"f5", "kemp", "nginx", "future-appliance"}, MissingFlags: []string{"--relay-claim"}},
			{Kind: "revocation.probe"},
			{Kind: "trust.distribute", MissingFlags: []string{"--relay-claim", "--host-exec-profile"}},
		}},
	}); err != nil {
		t.Fatalf("heartbeat with executor census: %v", err)
	}
	agent = readAgent()
	if agent["capability_source"] != "reported" || agent["reported_executor_version"] != "relay-0.9.1" || agent["capabilities_reported_at"] == nil {
		t.Fatalf("agent with a report = %v", agent)
	}
	// B6-1: the census says whether the host profile pins the native TLS
	// probe an ML-DSA host migration needs.
	if agent["reported_host_tls_probe"] != true {
		t.Fatalf("reported_host_tls_probe = %v, want true from the census", agent["reported_host_tls_probe"])
	}
	reported, _ := agent["reported_capabilities"].([]any)
	byKind := map[string]map[string]any{}
	for _, item := range reported {
		entry := item.(map[string]any)
		byKind[entry["kind"].(string)] = entry
	}
	deploy, ok := byKind["connector.deploy"]
	if !ok {
		t.Fatalf("reported list lacks connector.deploy: %v", reported)
	}
	// nginx is host work and this certificate says network, so it is filtered
	// out; a family this server does not know stays, because the report is
	// about the binary, not this build.
	if connectors := deploy["connectors"]; !jsonListEquals(connectors, []string{"f5", "kemp", "future-appliance"}) {
		t.Fatalf("reported connector.deploy connectors = %v", connectors)
	}
	if deploy["enabled"] != false || !jsonListEquals(deploy["missing_flags"], []string{"--relay-claim"}) {
		t.Fatalf("reported connector.deploy enabled/missing = %v / %v", deploy["enabled"], deploy["missing_flags"])
	}
	if probe, ok := byKind["revocation.probe"]; !ok || probe["enabled"] != true {
		t.Fatalf("reported revocation.probe = %v, want enabled with no missing flags", probe)
	}
	if _, ok := byKind["trust.distribute"]; ok {
		t.Fatal("a host-only kind was reported for a network-role certificate")
	}
	// The server census is still served beside it.
	if server, _ := agent["relay_capabilities"].([]any); len(server) == 0 {
		t.Fatal("the server census disappeared once the binary reported")
	}

	// An older report never overrides a newer one.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "relay-0.9.1", Status: "active"}); err != nil {
		t.Fatalf("later plain heartbeat: %v", err)
	}
	if agent = readAgent(); agent["capability_source"] != "reported" {
		t.Fatalf("a plain heartbeat erased the reported census: %v", agent)
	}
}

func jsonListEquals(value any, want []string) bool {
	list, ok := value.([]any)
	if !ok || len(list) != len(want) {
		return false
	}
	got := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok {
			return false
		}
		got = append(got, text)
	}
	return slices.Equal(got, want)
}
