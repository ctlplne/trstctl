// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// TestBrokerRequesterIsDerivedOrMarkedUnknownQ4L2: an agent's credential
// whose issuance names its requester, recorded or derived from the issuance
// event's actor, draws DELEGATED from that requester, the edge naming which;
// one whose issuance names none says requested_by "unknown" and draws no
// DELEGATED edge, so a reader never takes "no edge" for "nobody delegated".
func TestBrokerRequesterIsDerivedOrMarkedUnknownQ4L2(t *testing.T) {
	g := New()
	principals := principalIndex{}
	g.AddNode(Node{ID: "person:dana-ops", Kind: KindPerson, Name: "dana-ops"})
	principals["dana-ops"] = "person:dana-ops"
	g.AddNode(Node{ID: "person:eli-platform", Kind: KindPerson, Name: "eli-platform"})
	principals["eli-platform"] = "person:eli-platform"
	cert := func(id, agent, requestedBy, source string) store.Certificate {
		c := store.Certificate{ID: id, BrokerIssuance: &store.BrokerIssuance{AgentID: agent, Subject: agent + "-subject",
			RequestedBy: requestedBy, RequestedBySource: source}}
		node := certificateNode(c)
		node.ID = credentialID("cert", c.ID)
		g.AddNode(node)
		return c
	}
	certs := []store.Certificate{
		cert("c-derived", "agent-derived", "dana-ops", store.BrokerRequesterFromEventActor),
		cert("c-unknown", "agent-unknown", "", ""),
		cert("c-recorded", "agent-recorded", "eli-platform", ""),
	}
	addAIAgents(g, certs, principals, time.Now())
	delegated := map[string]Edge{}
	for _, e := range g.Edges() {
		if e.Type == EdgeDelegated {
			delegated[e.To] = e
		}
	}
	if e, ok := delegated["aiagent:agent-derived"]; !ok || e.From != "person:dana-ops" || e.Source != "agent broker issuance event actor" {
		t.Fatalf("the derived requester's edge = %+v (found %v)", e, ok)
	}
	if e, ok := delegated["aiagent:agent-recorded"]; !ok || e.From != "person:eli-platform" || e.Source != "agent broker issuance requester" {
		t.Fatalf("the recorded requester's edge = %+v (found %v)", e, ok)
	}
	if e, ok := delegated["aiagent:agent-unknown"]; ok {
		t.Fatalf("an issuance naming no requester drew %+v", e)
	}
	if node, ok := g.Node(credentialID("cert", "c-unknown")); !ok || node.Attrs["requested_by"] != "unknown" {
		t.Fatalf("the unnamed issuance's credential reads %+v; want requested_by unknown", node.Attrs)
	}
	for _, id := range []string{"c-derived", "c-recorded"} {
		if node, _ := g.Node(credentialID("cert", id)); node.Attrs["requested_by"] != "" {
			t.Fatalf("%s carries requested_by %q though its requester is known", id, node.Attrs["requested_by"])
		}
	}
}
