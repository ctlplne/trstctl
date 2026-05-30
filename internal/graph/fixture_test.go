package graph_test

import "certctl.io/certctl/internal/graph"

// fixture builds a small but representative credential graph used across the
// reachability, blast-radius, and Cypher tests:
//
//	Root CA ──ISSUED──▶ Intermediate CA ──ISSUED──▶ payments cert ──DEPLOYED_TO──▶ payments-db
//	                                     └─ISSUED──▶ web cert      ──DEPLOYED_TO──▶ lb-edge
//	payments-svc ─OWNS─▶ payments cert
//	web-frontend ─OWNS─▶ web cert
//	deploy-key   ─GRANTS_ACCESS─▶ bastion-host        (an un-owned, standing-access SSH grant)
//
// Edge direction is "impact flows From→To": compromising From puts To at risk,
// so a node's forward-reachable set is its blast radius.
func fixture() *graph.Graph {
	g := graph.New()

	nodes := []graph.Node{
		{ID: "iss:ca-root", Kind: graph.KindIssuer, Name: "Root CA"},
		{ID: "iss:ca-int", Kind: graph.KindIssuer, Name: "Intermediate CA"},
		{ID: "wl:payments", Kind: graph.KindWorkload, Name: "payments-svc"},
		{ID: "wl:web", Kind: graph.KindWorkload, Name: "web-frontend"},
		{ID: "cred:cert-payments", Kind: graph.KindCredential, Name: "payments.example.com"},
		{ID: "cred:cert-web", Kind: graph.KindCredential, Name: "web.example.com"},
		{ID: "cred:ssh-deploy", Kind: graph.KindCredential, Name: "deploy-key"},
		{ID: "res:payments-db", Kind: graph.KindResource, Name: "payments-db"},
		{ID: "res:lb-edge", Kind: graph.KindResource, Name: "lb-edge"},
		{ID: "res:bastion", Kind: graph.KindResource, Name: "bastion-host"},
	}
	for _, n := range nodes {
		g.AddNode(n)
	}

	edges := []graph.Edge{
		{From: "iss:ca-root", To: "iss:ca-int", Type: graph.EdgeIssued},
		{From: "iss:ca-int", To: "cred:cert-payments", Type: graph.EdgeIssued},
		{From: "iss:ca-int", To: "cred:cert-web", Type: graph.EdgeIssued},
		{From: "wl:payments", To: "cred:cert-payments", Type: graph.EdgeOwns},
		{From: "wl:web", To: "cred:cert-web", Type: graph.EdgeOwns},
		{From: "cred:cert-payments", To: "res:payments-db", Type: graph.EdgeDeployedTo},
		{From: "cred:cert-web", To: "res:lb-edge", Type: graph.EdgeDeployedTo},
		{From: "cred:ssh-deploy", To: "res:bastion", Type: graph.EdgeGrantsAccess},
	}
	for _, e := range edges {
		g.AddEdge(e)
	}
	return g
}

// ids extracts the node IDs of a node slice (nil for an empty slice, so leaf
// reachability compares cleanly against a nil want).
func ids(ns []graph.Node) []string {
	if len(ns) == 0 {
		return nil
	}
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.ID
	}
	return out
}
