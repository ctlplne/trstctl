// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"context"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// hostAgentID is the graph node of an enrolled host agent (G1-L3). AI agents
// the agent broker issued to are "aiagent:" nodes; the two never share an ID.
func hostAgentID(agentID string) string { return "agent:" + agentID }

// agentRoleID is the graph node of an agent capability role. Agent roles are
// a namespace of their own: a tenant role and an agent role of the same name
// are different grants.
func agentRoleID(role string) string { return "agent-role:" + role }

// addHostAgents adds every enrolled host agent as a workload node (G1-L3) and
// draws HAS_ROLE from it to each role its certificate carries: the roles the
// claim path reads, signed into the certificate's SANs. A role grant no
// renewal has signed yet grants nothing, so it is shown on the agent's node
// (pending_roles) rather than drawn. An offboarded agent keeps its node and
// holds no role.
func addHostAgents(ctx context.Context, st *store.Store, tenantID string, g *Graph, _ principalIndex, _ time.Time) error {
	var agents []store.Agent
	var afterCreated *time.Time
	afterID := ""
	for {
		page, err := st.ListAgentsPage(ctx, tenantID, afterCreated, afterID, pageSize)
		if err != nil {
			return err
		}
		agents = append(agents, page...)
		if len(page) < pageSize {
			break
		}
		last := page[len(page)-1]
		afterCreated, afterID = &last.CreatedAt, last.ID
	}
	for start := 0; start < len(agents); start += pageSize {
		batch := agents[start:min(start+pageSize, len(agents))]
		ids := make([]string, 0, len(batch))
		for _, a := range batch {
			ids = append(ids, a.ID)
		}
		grants, err := st.AgentRoleGrants(ctx, tenantID, ids)
		if err != nil {
			return err
		}
		for _, a := range batch {
			addHostAgent(g, a, grants[a.ID])
		}
	}
	return nil
}

func addHostAgent(g *Graph, a store.Agent, grant store.AgentRoleGrant) {
	id := hostAgentID(a.ID)
	attrs := map[string]string{"workload_kind": "host_agent", "agent_id": a.ID, "status": a.Status}
	if a.Version != "" {
		attrs["version"] = a.Version
	}
	if a.LastSeenAt != nil {
		attrs["last_seen_at"] = a.LastSeenAt.UTC().Format(time.RFC3339)
	}
	if a.OffboardedAt != nil {
		attrs["offboarded_at"] = a.OffboardedAt.UTC().Format(time.RFC3339)
		g.AddNode(Node{ID: id, Kind: KindWorkload, Name: firstNonEmpty(a.Name, a.ID), Attrs: attrs})
		return
	}
	roles := sortedRoles(a.Roles)
	attrs["roles"] = strings.Join(roles, ",")
	if grant.AgentID != "" && grant.Pending() {
		attrs["pending_roles"] = strings.Join(sortedRoles(grant.Roles), ",")
	}
	g.AddNode(Node{ID: id, Kind: KindWorkload, Name: firstNonEmpty(a.Name, a.ID), Attrs: attrs})
	for _, role := range roles {
		g.AddNode(Node{ID: agentRoleID(role), Kind: KindRole, Name: role, Attrs: map[string]string{"role_scope": "agent"}})
		g.AddEdge(Edge{From: id, To: agentRoleID(role), Type: EdgeHasRole, Source: "agent certificate", Confidence: confidenceAuthority})
	}
}

// sortedRoles returns the distinct, non-empty roles in order, so a node's
// attributes and edges do not depend on the order a certificate listed them.
func sortedRoles(roles []string) []string {
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		if role = strings.TrimSpace(role); role != "" {
			out = append(out, role)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
