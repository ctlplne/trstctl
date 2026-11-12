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

type g1l3Node struct {
	ID    string            `json:"id"`
	Kind  string            `json:"kind"`
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs"`
}

type g1l3Edge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Type       string `json:"type"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

// readG1L3Graph reads the tenant's graph as the token's holder.
func readG1L3Graph(t *testing.T, h *servedHarness, token string) (map[string]g1l3Node, []g1l3Edge, bool) {
	t.Helper()
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/graph", token, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/graph = %d %s", status, raw)
	}
	var g struct {
		Nodes         []g1l3Node `json:"nodes"`
		Edges         []g1l3Edge `json:"edges"`
		AccessOmitted bool       `json:"access_omitted"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]g1l3Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	return nodes, g.Edges, g.AccessOmitted
}

// roleEdgesFrom lists the HAS_ROLE targets drawn from one node.
func roleEdgesFrom(edges []g1l3Edge, from string) []g1l3Edge {
	var out []g1l3Edge
	for _, e := range edges {
		if e.From == from && e.Type == "HAS_ROLE" {
			out = append(out, e)
		}
	}
	return out
}

// TestServedGraphNamesEnrolledHostAgentsAndTheirRolesG1L3 is G1-L3: an
// enrolled host agent is a workload in the graph, with HAS_ROLE to each agent
// role its certificate carries, so "which machines may run network probes"
// is a graph query. A grant no renewal has signed yet is shown on the agent,
// not drawn, because it grants nothing until then. An offboarded agent holds
// no role. Agents and their roles are access data: a reader without
// access:read gets the graph without them.
func TestServedGraphNamesEnrolledHostAgentsAndTheirRolesG1L3(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessNamedWithEventOptions(t, "g1l3-edge", []string{mtls.AgentRoleHost}, nil, nil)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "g1l3", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	agentID := agentRowID(h.tenant, h.agent)
	nodeID := "agent:" + agentID
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "g1l3-auditor", "graph:read", "access:read")
	graphOnly := seedScopedTokenSubject(t, h.store, h.tenant, "g1l3-graph-viewer", "graph:read")

	nodes, edges, omitted := readG1L3Graph(t, h.servedHarness, auditor)
	agent, ok := nodes[nodeID]
	if omitted || !ok || agent.Kind != "workload" || agent.Name != h.agent || agent.Attrs["workload_kind"] != "host_agent" ||
		agent.Attrs["agent_id"] != agentID || agent.Attrs["roles"] != mtls.AgentRoleHost || agent.Attrs["status"] != "active" ||
		agent.Attrs["pending_roles"] != "" {
		t.Fatalf("enrolled agent node = %+v (present %v, access omitted %v); want a host_agent workload with its host role", agent, ok, omitted)
	}
	roleEdges := roleEdgesFrom(edges, nodeID)
	if len(roleEdges) != 1 || roleEdges[0].To != "agent-role:"+mtls.AgentRoleHost || roleEdges[0].Source != "agent certificate" ||
		roleEdges[0].Confidence != "authoritative" {
		t.Fatalf("agent role edges = %+v; want one authoritative HAS_ROLE to its certificate's host role", roleEdges)
	}
	if role := nodes["agent-role:"+mtls.AgentRoleHost]; role.Kind != "role" || role.Name != mtls.AgentRoleHost || role.Attrs["role_scope"] != "agent" {
		t.Fatalf("agent role node = %+v", role)
	}

	// A grant the next renewal will sign is shown, not drawn.
	granter := seedScopedToken(t, h.store, h.tenant, "agents:relay.grant")
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/"+agentID+"/roles", granter, "g1l3-grant",
		map[string]any{"roles": []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}, "reason": "probe the plant network"}); code != http.StatusOK {
		t.Fatalf("grant = %d %s", code, body)
	}
	nodes, edges, _ = readG1L3Graph(t, h.servedHarness, auditor)
	if got := nodes[nodeID].Attrs; got["pending_roles"] != mtls.AgentRoleHost+","+mtls.AgentRoleNetwork || got["roles"] != mtls.AgentRoleHost {
		t.Fatalf("agent attributes after the grant = %v; want the signed host role and the pending host,network grant", got)
	}
	if roleEdges := roleEdgesFrom(edges, nodeID); len(roleEdges) != 1 || roleEdges[0].To != "agent-role:"+mtls.AgentRoleHost {
		t.Fatalf("agent role edges after an unsigned grant = %+v; want only the signed role", roleEdges)
	}

	// Which machines hold a role is a graph query.
	status, raw := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/graph/query", auditor,
		map[string]string{"query": `MATCH (a:workload)-[:HAS_ROLE]->(r:role) WHERE r.name = "host" RETURN a.name`})
	var result struct {
		Rows []map[string]string `json:"rows"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &result) != nil || !slices.ContainsFunc(result.Rows, func(r map[string]string) bool { return r["a.name"] == h.agent }) {
		t.Fatalf("query for agents holding the host role = %d %s; want %s", status, raw, h.agent)
	}

	// Agents and their roles are access data.
	narrow, narrowEdges, omitted := readG1L3Graph(t, h.servedHarness, graphOnly)
	if _, leaked := narrow[nodeID]; leaked || !omitted || len(roleEdgesFrom(narrowEdges, nodeID)) != 0 {
		t.Fatalf("graph for graph:read alone: agent present %v, access omitted %v", leaked, omitted)
	}

	// An offboarded agent keeps its node and holds no role.
	offboarder := seedScopedToken(t, h.store, h.tenant, "agents:write", "agents:read")
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/"+agentID+"/offboard", offboarder, "g1l3-offboard",
		map[string]any{"reason": "host decommissioned"}); code != http.StatusOK {
		t.Fatalf("offboard = %d %s", code, body)
	}
	nodes, edges, _ = readG1L3Graph(t, h.servedHarness, auditor)
	if gone := nodes[nodeID]; gone.Attrs["offboarded_at"] == "" || gone.Attrs["roles"] != "" || len(roleEdgesFrom(edges, nodeID)) != 0 {
		t.Fatalf("offboarded agent node = %+v, role edges %+v; want the node with no role", gone, roleEdgesFrom(edges, nodeID))
	}
}
