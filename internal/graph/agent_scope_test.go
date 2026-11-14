// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"strings"
	"testing"
)

// Q4: a broker scope names the tool it reaches; Q4-L3: and the action it
// allows there.
func TestAgentScopeResourceNamesTheTool(t *testing.T) {
	t.Parallel()
	g := New()
	for scope, want := range map[string][2]string{
		"tool:inventory.read":    {"res:agent-scope:tool:inventory", "read"},
		"mcp:graph.read":         {"res:agent-scope:mcp:graph", "read"},
		"tool:billing.v2.write":  {"res:agent-scope:tool:billing.v2", "write"},
		"admin":                  {"res:agent-scope:admin", ""},
		"tool:records":           {"res:agent-scope:tool:records", ""},
		"weird.name:with.colons": {"res:agent-scope:weird.name:with", "colons"},
	} {
		if id, action := agentScopeResource(g, scope); id != want[0] || action != want[1] {
			t.Errorf("agentScopeResource(%q) = %q %q, want %q %q", scope, id, action, want[0], want[1])
		}
	}
	if n, ok := g.Node("res:agent-scope:tool:inventory"); !ok || n.Kind != KindResource || n.Attrs["resource_kind"] != "agent_scope" {
		t.Fatalf("scope resource node = %+v, %t", n, ok)
	}
}

// Q4-L3 Done-when (graph): a scope's action is on the access grant. One
// agent reads the inventory tool and another writes it; the answer for write
// lists only the writer's credential, and for read only the reader's. Two
// scopes on one tool join on one grant, a scope without an action keeps the
// grant unnarrowed, and a grant that names no action (a PAM session) stays in
// every answer.
func TestScopeActionsNarrowWhoCanReachQ4L3(t *testing.T) {
	t.Parallel()
	g := New()
	tool := "res:agent-scope:tool:inventory"
	g.AddNode(Node{ID: tool, Kind: KindResource, Name: "tool:inventory"})
	for _, c := range []string{"cert:reader", "cert:writer", "cert:both", "cert:all", "cred:pam"} {
		g.AddNode(Node{ID: c, Kind: KindCredential, Name: c})
	}
	grant := func(from string, actions ...string) {
		g.AddEdge(Edge{From: from, To: tool, Type: EdgeGrantsAccess, Source: "agent broker scope", Actions: actions})
	}
	grant("cert:reader", "read")
	grant("cert:writer", "write")
	grant("cert:both", "write")
	grant("cert:both", "read")
	grant("cert:both", "read")
	grant("cert:all", "read")
	grant("cert:all")
	grant("cert:all", "write")
	g.AddEdge(Edge{From: "cred:pam", To: tool, Type: EdgeGrantsAccess, Source: "pam session"})

	actions := map[string][]string{}
	for _, e := range g.Edges() {
		actions[e.From] = e.Actions
	}
	if got := actions["cert:both"]; len(got) != 2 || got[0] != "read" || got[1] != "write" {
		t.Fatalf("two scopes on one tool = %v, want [read write]", got)
	}
	if got := actions["cert:all"]; got != nil {
		t.Fatalf("a scope without an action left the grant narrowed to %v", got)
	}
	reachers := func(action string) []string {
		var out []string
		for _, grant := range g.WhoCanReachFor(tool, action).Access {
			out = append(out, grant.Credential.ID)
		}
		return out
	}
	for action, want := range map[string]string{
		"write": "cert:all cert:both cert:writer cred:pam",
		"read":  "cert:all cert:both cert:reader cred:pam",
		"":      "cert:all cert:both cert:reader cert:writer cred:pam",
	} {
		if got := strings.Join(reachers(action), " "); got != want {
			t.Errorf("who can reach the tool for %q = %s, want %s", action, got, want)
		}
	}
	if got := g.WhoCanReachFor(tool, "write"); got.Action != "write" {
		t.Fatalf("the answer does not say which action it is for: %+v", got)
	}
}
