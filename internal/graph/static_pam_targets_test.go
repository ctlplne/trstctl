// SPDX-License-Identifier: BUSL-1.1

package graph

import "testing"

// G1-L5: a statically configured PAM target joins the graph linked to its
// provider's backend; one a session already put in the graph is marked
// static with its provider, not added twice; one naming no provider gets no
// link.
func TestStaticPAMTargetsConnectToTheirProviderG1L5(t *testing.T) {
	g := New()
	existing := pamTargetResourceID("mysql", "inv-db")
	g.AddNode(Node{ID: existing, Kind: KindResource, Name: "inv-db", Attrs: map[string]string{"resource_kind": "pam_target", "target_type": "mysql"}})
	addStaticPAMTargets(g, []PAMTargetRef{
		{TargetType: "postgres", ID: "orders-db", ProviderID: "pg-orders"},
		{TargetType: "mysql", ID: "inv-db", ProviderID: "my-inv"},
		{TargetType: "mongodb", ID: "events", ProviderID: ""},
	})
	for id, provider := range map[string]string{pamTargetResourceID("postgres", "orders-db"): "pg-orders", existing: "my-inv"} {
		n, ok := g.nodes[id]
		if !ok || n.Attrs["configured"] != "static" || n.Attrs["provider_id"] != provider {
			t.Fatalf("%s = %+v (found %v)", id, n, ok)
		}
		linked := false
		for _, e := range g.edges {
			if e.From == id && e.To == resourceID("dynamic-secret:"+provider) && e.Type == EdgeConnectsTo {
				linked = true
			}
		}
		if !linked {
			t.Fatalf("%s has no CONNECTS_TO edge to its provider's backend", id)
		}
	}
	for _, e := range g.edges {
		if e.From == pamTargetResourceID("mongodb", "events") {
			t.Fatalf("a target naming no provider got an edge: %+v", e)
		}
	}
}
