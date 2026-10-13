// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

func TestMigrationAssessmentCountsOnlyAssignedAgentTrustStores(t *testing.T) {
	t.Parallel()
	g := graph.New()
	g.AddNode(graph.Node{ID: "ts:assigned:os", Kind: graph.KindTrustStore,
		Attrs: map[string]string{"host": "assigned-host", "agent_id": "11111111-1111-4111-8111-111111111111"}})
	g.AddNode(graph.Node{ID: "ts:other:os", Kind: graph.KindTrustStore,
		Attrs: map[string]string{"host": "target-display-name", "agent_id": "22222222-2222-4222-8222-222222222222"}})
	g.AddNode(graph.Node{ID: "ts:legacy:os", Kind: graph.KindTrustStore,
		Attrs: map[string]string{"host": "assigned-host"}})
	target := store.DeploymentTarget{Name: "target-display-name", Config: json.RawMessage(`{
		"executor":"agent", "required_agent_id":"11111111-1111-4111-8111-111111111111",
		"required_agent_role":"host"}`)}
	if got := observedMigrationTrustStores(g, target); got != 1 {
		t.Fatalf("observed stores = %d, want only the verified assigned host's store; display-name collision and legacy name-only finding cannot authorize migration", got)
	}
	target.Config = json.RawMessage(`{"executor":"agent", "required_agent_role":"host"}`)
	if got := observedMigrationTrustStores(g, target); got != 0 {
		t.Fatalf("unbound target observed stores = %d, want 0", got)
	}
}
