// SPDX-License-Identifier: BUSL-1.1

package graph

import "testing"

// Q4: a broker scope names the tool it reaches; the action stays with the scope.
func TestAgentScopeResourceNamesTheTool(t *testing.T) {
	t.Parallel()
	g := New()
	for scope, want := range map[string]string{
		"tool:inventory.read":    "res:agent-scope:tool:inventory",
		"mcp:graph.read":         "res:agent-scope:mcp:graph",
		"tool:billing.v2.write":  "res:agent-scope:tool:billing.v2",
		"admin":                  "res:agent-scope:admin",
		"tool:records":           "res:agent-scope:tool:records",
		"weird.name:with.colons": "res:agent-scope:weird.name:with",
	} {
		if got := agentScopeResource(g, scope); got != want {
			t.Errorf("agentScopeResource(%q) = %q, want %q", scope, got, want)
		}
	}
	if n, ok := g.Node("res:agent-scope:tool:inventory"); !ok || n.Kind != KindResource || n.Attrs["resource_kind"] != "agent_scope" {
		t.Fatalf("scope resource node = %+v, %t", n, ok)
	}
}
