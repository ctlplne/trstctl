// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"strings"
	"testing"
	"time"
)

// Q4-L4 Done-when (graph): an AGID chain-bound credential is in the access
// graph with its delegation chain. alice delegated to planner, planner to
// worker, and worker holds the credential, which passes on the tool fs for
// read and the database orders for read. Who can reach the tool lists the
// credential, held by worker, with the chain back to alice; a revoked
// credential, one under an expired record and one whose chain could not be
// read grant nothing but are still shown held.
func TestAgentChainsDrawTheDelegationChainQ4L4(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	hour := time.Hour
	links := []AgentDelegationLink{
		{DelegatorID: "alice@ops.example", DelegateID: "planner", NotBefore: now.Add(-hour), NotAfter: now.Add(hour)},
		{DelegatorID: "planner", DelegateID: "worker", NotBefore: now.Add(-hour), NotAfter: now.Add(hour)},
	}
	chain := func(id string, change func(*AgentChain)) AgentChain {
		c := AgentChain{CredentialID: id, SubjectID: "worker", NotBefore: now.Add(-hour), NotAfter: now.Add(hour),
			Links: links, Tools: []string{"fs.read"}, Resources: []AgentChainResource{{Kind: "db", Value: "orders"}}, Scopes: []string{"read"}}
		if change != nil {
			change(&c)
		}
		return c
	}
	expired := append([]AgentDelegationLink(nil), links...)
	expired[1].NotAfter = now.Add(-time.Minute)
	g := New()
	principals := principalIndex{}
	g.AddNode(Node{ID: "person:alice@ops.example", Kind: KindPerson, Name: "Alice Ops"})
	principals["alice@ops.example"] = "person:alice@ops.example"
	addAgentChains(g, []AgentChain{
		chain("live", nil),
		chain("revoked", func(c *AgentChain) { c.Revoked = true }),
		chain("stale", func(c *AgentChain) { c.Links = expired }),
		chain("broken", func(c *AgentChain) { c.ChainBroken, c.Links = true, nil }),
	}, false, principals, now)

	answer := g.WhoCanReach("res:agent-scope:tool:fs")
	if len(answer.Access) != 1 || answer.Access[0].Credential.ID != "agid:live" ||
		strings.Join(answer.Access[0].Grant.Actions, ",") != "read" {
		t.Fatalf("who can reach the fs tool = %+v", answer.Access)
	}
	grant := answer.Access[0]
	if len(grant.Holders) != 1 || grant.Holders[0].Node.ID != "principal:worker" || grant.Holders[0].Edge.Source != "agent chain-bound issuance" {
		t.Fatalf("holders = %+v", grant.Holders)
	}
	var chainText []string
	for _, d := range grant.Delegations {
		chainText = append(chainText, d.Edge.From+">"+d.Edge.To)
	}
	if got := strings.Join(chainText, " "); got != "principal:planner>principal:worker person:alice@ops.example>principal:planner" {
		t.Fatalf("delegations = %s", got)
	}
	if path, ok := g.PathBetween("person:alice@ops.example", "res:agent-resource:db:orders"); !ok || len(path.Edges) != 4 ||
		strings.Join(path.Edges[3].Actions, ",") != "read" {
		t.Fatalf("alice → planner → worker → credential → orders = %+v %t", path, ok)
	}
	for _, id := range []string{"agid:revoked", "agid:stale", "agid:broken"} {
		n, ok := g.Node(id)
		if !ok || len(g.incomingLinks(id, EdgeHolds)) != 1 {
			t.Fatalf("%s is not shown held: %+v", id, n)
		}
		for _, e := range g.Edges() {
			if e.From == id && e.Type == EdgeGrantsAccess {
				t.Fatalf("%s grants access: %+v", id, e)
			}
		}
	}
	if n, _ := g.Node("agid:revoked"); n.Attrs["revoked"] != "true" {
		t.Fatalf("revoked attrs = %v", n.Attrs)
	}
	if n, _ := g.Node("agid:broken"); n.Attrs["chain_broken"] != "true" {
		t.Fatalf("broken attrs = %v", n.Attrs)
	}
}
