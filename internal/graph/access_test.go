// SPDX-License-Identifier: BUSL-1.1

package graph_test

import (
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/graph"
)

// accessFixture is a database reached through one PAM session: a person
// requested it, a workload was attested to it, two people approved it. A
// second person holds an API token to the trstctl API. An AI agent holds a
// certificate deployed to a host.
func accessFixture() *graph.Graph {
	g := graph.New()
	for _, n := range []graph.Node{
		{ID: "person:alice", Kind: graph.KindPerson, Name: "Alice"},
		{ID: "person:bob", Kind: graph.KindPerson, Name: "Bob"},
		{ID: "person:carol", Kind: graph.KindPerson, Name: "Carol"},
		{ID: "role:operator", Kind: graph.KindRole, Name: "operator"},
		{ID: "principal:spiffe://lab/app", Kind: graph.KindWorkload, Name: "spiffe://lab/app"},
		{ID: "aiagent:triage", Kind: graph.KindAIAgent, Name: "triage"},
		{ID: "pam:s1", Kind: graph.KindCredential, Name: "readonly@pg-main"},
		{ID: "token:t1", Kind: graph.KindCredential, Name: "API token for carol"},
		{ID: "cert:agent", Kind: graph.KindCredential, Name: "triage cert"},
		{ID: "res:pam:postgres:pg-main", Kind: graph.KindResource, Name: "pg-main"},
		{ID: "res:dynamic-secret:pg", Kind: graph.KindResource, Name: "pg"},
		{ID: "res:trstctl-api", Kind: graph.KindResource, Name: "trstctl API"},
		{ID: "res:host-1", Kind: graph.KindResource, Name: "host-1"},
	} {
		g.AddNode(n)
	}
	auth := "authoritative"
	for _, e := range []graph.Edge{
		{From: "person:alice", To: "role:operator", Type: graph.EdgeHasRole, Source: "tenant membership", Confidence: auth},
		{From: "person:alice", To: "pam:s1", Type: graph.EdgeHolds, Source: "PAM session requester", Confidence: auth},
		{From: "principal:spiffe://lab/app", To: "pam:s1", Type: graph.EdgeHolds, Source: "PAM session attested workload", Confidence: auth},
		{From: "person:bob", To: "pam:s1", Type: graph.EdgeApproved, Source: "PAM approval decision", Confidence: auth},
		{From: "person:carol", To: "pam:s1", Type: graph.EdgeApproved, Source: "PAM approval decision", Confidence: auth},
		{From: "pam:s1", To: "res:pam:postgres:pg-main", Type: graph.EdgeGrantsAccess, Source: "PAM session grant", Confidence: auth},
		{From: "res:pam:postgres:pg-main", To: "res:dynamic-secret:pg", Type: graph.EdgeConnectsTo, Source: "PAM target provider reference", Confidence: auth},
		{From: "person:carol", To: "token:t1", Type: graph.EdgeHolds, Source: "API token subject", Confidence: auth},
		{From: "token:t1", To: "res:trstctl-api", Type: graph.EdgeGrantsAccess, Source: "API token scopes", Confidence: auth},
		{From: "aiagent:triage", To: "cert:agent", Type: graph.EdgeHolds, Source: "agent broker issuance", Confidence: auth},
		{From: "cert:agent", To: "res:host-1", Type: graph.EdgeDeployedTo, Source: "certificate deployment inventory", Confidence: "observed"},
	} {
		g.AddEdge(e)
	}
	return g
}

func TestWhoCanReachNamesHolderCredentialAndApproverWithConfidence(t *testing.T) {
	t.Parallel()
	got := accessFixture().WhoCanReach("res:pam:postgres:pg-main")
	if got.Target.ID != "res:pam:postgres:pg-main" {
		t.Fatalf("target = %+v", got.Target)
	}
	if len(got.Access) != 1 {
		t.Fatalf("access = %+v, want the one PAM session", got.Access)
	}
	grant := got.Access[0]
	if grant.Credential.ID != "pam:s1" || grant.Grant.Type != graph.EdgeGrantsAccess || grant.Grant.Confidence != "authoritative" {
		t.Fatalf("grant = %+v", grant)
	}
	var holders, approvers []string
	for _, l := range grant.Holders {
		holders = append(holders, l.Node.ID+"|"+l.Edge.Source+"|"+l.Edge.Confidence)
	}
	for _, l := range grant.Approvers {
		approvers = append(approvers, l.Node.ID+"|"+l.Edge.Source+"|"+l.Edge.Confidence)
	}
	if want := []string{
		"person:alice|PAM session requester|authoritative",
		"principal:spiffe://lab/app|PAM session attested workload|authoritative",
	}; !reflect.DeepEqual(holders, want) {
		t.Fatalf("holders = %v, want %v", holders, want)
	}
	if want := []string{"person:bob|PAM approval decision|authoritative", "person:carol|PAM approval decision|authoritative"}; !reflect.DeepEqual(approvers, want) {
		t.Fatalf("approvers = %v, want %v", approvers, want)
	}
	// Reachers are the reverse of blast radius: the holders and the session,
	// never the approvers (approving is not a path an attacker travels).
	if want := []string{"pam:s1", "person:alice", "principal:spiffe://lab/app"}; !reflect.DeepEqual(ids(got.Reachers), want) {
		t.Fatalf("reachers = %v, want %v", ids(got.Reachers), want)
	}
	for _, path := range got.Paths {
		if path.Target.ID != got.Target.ID || path.Nodes[len(path.Nodes)-1].ID != got.Target.ID || len(path.Edges) != len(path.Nodes)-1 {
			t.Fatalf("reverse path does not end at the target: %+v", path)
		}
	}
	if got.Coverage.Note == "" || len(got.Coverage.NotCovered) == 0 {
		t.Fatalf("coverage must say what the answer cannot see: %+v", got.Coverage)
	}
}

func TestWhoCanReachFollowsAccessThroughAConnectedBackend(t *testing.T) {
	t.Parallel()
	got := accessFixture().WhoCanReach("res:dynamic-secret:pg")
	if len(got.Access) != 1 || got.Access[0].Credential.ID != "pam:s1" {
		t.Fatalf("access through the PAM target = %+v", got.Access)
	}
	if want := []string{"pam:s1", "res:pam:postgres:pg-main", "res:dynamic-secret:pg"}; !reflect.DeepEqual(ids(got.Access[0].Path.Nodes), want) {
		t.Fatalf("path = %v, want %v", ids(got.Access[0].Path.Nodes), want)
	}
}

func TestWhoCanReachAnUnknownOrUnreachedNodeIsEmptyNotNull(t *testing.T) {
	t.Parallel()
	g := accessFixture()
	for _, id := range []string{"nope", "person:bob"} {
		got := g.WhoCanReach(id)
		if got.Reachers == nil || got.Access == nil || got.Paths == nil || got.ByKind == nil {
			t.Fatalf("WhoCanReach(%s) returned a nil list: %+v", id, got)
		}
		if len(got.Access) != 0 {
			t.Fatalf("WhoCanReach(%s) access = %+v", id, got.Access)
		}
	}
}

func TestApprovalIsEvidenceNotBlastRadius(t *testing.T) {
	t.Parallel()
	g := accessFixture()
	if got := ids(g.BlastRadius("person:bob").Affected); len(got) != 0 {
		t.Fatalf("an approver's blast radius = %v, want none", got)
	}
	if got := ids(g.Reachable("person:bob", graph.EdgeApproved)); !reflect.DeepEqual(got, []string{"pam:s1"}) {
		t.Fatalf("an explicit APPROVED traversal = %v", got)
	}
	if got := ids(g.BlastRadius("person:alice").Affected); !reflect.DeepEqual(got, []string{"pam:s1", "res:dynamic-secret:pg", "res:pam:postgres:pg-main", "role:operator"}) {
		t.Fatalf("a holder's blast radius = %v", got)
	}
}

func TestPathBetweenIsTheShortestEvidenceChain(t *testing.T) {
	t.Parallel()
	g := accessFixture()
	path, ok := g.PathBetween("person:alice", "res:dynamic-secret:pg")
	if !ok {
		t.Fatal("no path from the requester to the backend")
	}
	if want := []string{"person:alice", "pam:s1", "res:pam:postgres:pg-main", "res:dynamic-secret:pg"}; !reflect.DeepEqual(ids(path.Nodes), want) {
		t.Fatalf("path = %v, want %v", ids(path.Nodes), want)
	}
	if path.Edges[0].Type != graph.EdgeHolds || path.Edges[0].Source != "PAM session requester" {
		t.Fatalf("first hop = %+v", path.Edges[0])
	}
	for _, pair := range [][2]string{{"person:bob", "res:pam:postgres:pg-main"}, {"res:trstctl-api", "person:carol"}, {"person:alice", "person:alice"}, {"nope", "res:host-1"}} {
		if _, ok := g.PathBetween(pair[0], pair[1]); ok {
			t.Fatalf("PathBetween(%s, %s) found a path", pair[0], pair[1])
		}
	}
	agentPath, ok := g.PathBetween("aiagent:triage", "res:host-1")
	if !ok || len(agentPath.Nodes) != 3 {
		t.Fatalf("AI agent path = %+v, %t", agentPath, ok)
	}
}

func TestReverseEvidencePathsAreStableAcrossInsertionOrder(t *testing.T) {
	t.Parallel()
	a := accessFixture()
	b := graph.New()
	nodes, edges := a.Nodes(), a.Edges()
	for i := len(nodes) - 1; i >= 0; i-- {
		b.AddNode(nodes[i])
	}
	for i := len(edges) - 1; i >= 0; i-- {
		b.AddEdge(edges[i])
	}
	for _, id := range []string{"res:dynamic-secret:pg", "res:trstctl-api", "res:host-1"} {
		if !reflect.DeepEqual(a.WhoCanReach(id), b.WhoCanReach(id)) {
			t.Fatalf("WhoCanReach(%s) depends on insertion order", id)
		}
	}
}
