package graph_test

import (
	"reflect"
	"sort"
	"testing"

	"trstctl.com/trstctl/internal/graph"
)

func TestNodesAndEdgesAreIdempotent(t *testing.T) {
	g := fixture()
	if g.Order() != 10 {
		t.Errorf("Order() = %d, want 10", g.Order())
	}
	if g.Size() != 8 {
		t.Errorf("Size() = %d, want 8", g.Size())
	}
	// Re-adding the same node and edge must not duplicate.
	g.AddNode(graph.Node{ID: "iss:ca-root", Kind: graph.KindIssuer, Name: "Root CA"})
	g.AddEdge(graph.Edge{From: "iss:ca-root", To: "iss:ca-int", Type: graph.EdgeIssued})
	if g.Order() != 10 || g.Size() != 8 {
		t.Errorf("re-adding duplicated: Order=%d Size=%d", g.Order(), g.Size())
	}
	if _, ok := g.Node("res:bastion"); !ok {
		t.Error("Node(res:bastion) not found")
	}
	if _, ok := g.Node("nope"); ok {
		t.Error("Node(nope) unexpectedly found")
	}
}

func TestNeighbors(t *testing.T) {
	g := fixture()
	got := ids(g.Neighbors("iss:ca-int", graph.EdgeIssued))
	sort.Strings(got)
	want := []string{"cred:cert-payments", "cred:cert-web"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Neighbors(ca-int, ISSUED) = %v, want %v", got, want)
	}
	// Unfiltered neighbors include every out-edge target.
	if n := len(g.Neighbors("iss:ca-int")); n != 2 {
		t.Errorf("unfiltered neighbor count = %d, want 2", n)
	}
	// A leaf resource has no out-neighbors.
	if n := len(g.Neighbors("res:payments-db")); n != 0 {
		t.Errorf("leaf neighbor count = %d, want 0", n)
	}
}

func TestReachable(t *testing.T) {
	g := fixture()

	cases := []struct {
		from string
		want []string
	}{
		{"iss:ca-root", []string{"cred:cert-payments", "cred:cert-web", "iss:ca-int", "res:lb-edge", "res:payments-db"}},
		{"iss:ca-int", []string{"cred:cert-payments", "cred:cert-web", "res:lb-edge", "res:payments-db"}},
		{"wl:payments", []string{"cred:cert-payments", "res:payments-db"}},
		{"cred:ssh-deploy", []string{"res:bastion"}},
		{"res:payments-db", nil}, // a leaf reaches nothing
	}
	for _, c := range cases {
		got := ids(g.Reachable(c.from))
		sort.Strings(got)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Reachable(%s) = %v, want %v", c.from, got, c.want)
		}
	}
}

func TestReachableEdgeTypeFilter(t *testing.T) {
	g := fixture()
	// Following only ISSUED edges from the root reaches the CA chain and the
	// issued certs, but not the resources (which are reached via DEPLOYED_TO).
	got := ids(g.Reachable("iss:ca-root", graph.EdgeIssued))
	sort.Strings(got)
	want := []string{"cred:cert-payments", "cred:cert-web", "iss:ca-int"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Reachable(ca-root, ISSUED) = %v, want %v", got, want)
	}
}

func TestReaches(t *testing.T) {
	g := fixture()
	cases := []struct {
		from, to string
		want     bool
	}{
		{"iss:ca-root", "res:payments-db", true}, // root → int → cert → db
		{"iss:ca-int", "res:lb-edge", true},
		{"wl:web", "res:payments-db", false}, // different subtree
		{"cred:ssh-deploy", "res:bastion", true},
		{"res:payments-db", "iss:ca-root", false}, // edges are directed
		{"wl:payments", "wl:payments", false},     // a node does not reach itself
	}
	for _, c := range cases {
		if got := g.Reaches(c.from, c.to); got != c.want {
			t.Errorf("Reaches(%s, %s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestBlastRadius(t *testing.T) {
	g := fixture()

	// Compromising the root CA affects the intermediate, every cert it issued,
	// and every resource those certs protect.
	imp := g.BlastRadius("iss:ca-root")
	gotAll := ids(imp.Affected)
	sort.Strings(gotAll)
	wantAll := []string{"cred:cert-payments", "cred:cert-web", "iss:ca-int", "res:lb-edge", "res:payments-db"}
	if !reflect.DeepEqual(gotAll, wantAll) {
		t.Errorf("BlastRadius(ca-root).Affected = %v, want %v", gotAll, wantAll)
	}

	gotCreds := ids(imp.ByKind[graph.KindCredential])
	sort.Strings(gotCreds)
	if want := []string{"cred:cert-payments", "cred:cert-web"}; !reflect.DeepEqual(gotCreds, want) {
		t.Errorf("affected credentials = %v, want %v", gotCreds, want)
	}
	gotRes := ids(imp.ByKind[graph.KindResource])
	sort.Strings(gotRes)
	if want := []string{"res:lb-edge", "res:payments-db"}; !reflect.DeepEqual(gotRes, want) {
		t.Errorf("affected resources = %v, want %v", gotRes, want)
	}
	if imp.Node.ID != "iss:ca-root" {
		t.Errorf("Impact.Node = %q, want iss:ca-root", imp.Node.ID)
	}

	// A single workload's blast radius is just its own credential and where it
	// is deployed — not the unrelated web subtree.
	imp2 := g.BlastRadius("wl:payments")
	got2 := ids(imp2.Affected)
	sort.Strings(got2)
	if want := []string{"cred:cert-payments", "res:payments-db"}; !reflect.DeepEqual(got2, want) {
		t.Errorf("BlastRadius(payments-svc).Affected = %v, want %v", got2, want)
	}
}
