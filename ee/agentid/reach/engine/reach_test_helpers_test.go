// SPDX-License-Identifier: LicenseRef-trstctl-EE

package engine_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/ee/agentid/reach"
	"trstctl.com/trstctl/ee/agentid/reach/engine"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

// reach_test_helpers_test.go holds the shared test scaffolding for the reachability engine
// package: an in-memory GraphSource, a fixture credential graph with labeled assets, and a
// software verdict signer + trust lookup. It lives with the engine tests (as an external
// engine_test package) because it drives the engine (which needs internal/graph); the
// crypto-only reach package's own verdict/ceiling/verify tests import both reach and this
// engine subpackage. No datastore is stood up here (the RLS test that needs one has its own
// embedded-Postgres TestMain under reach/reachpg); these helpers keep the engine/verdict/
// verify unit and property tests fast and deterministic.

// staticGraphSource is an in-memory engine.GraphSource: it returns a fixed graph and
// watermark for a tenant, so the engine can be driven without a datastore. It lets a test
// mutate the graph or bump the watermark to assert cache/freshness behavior.
type staticGraphSource struct {
	byTenant map[string]*graph.Graph
	wmByTen  map[string]string
}

func newStaticGraphSource() *staticGraphSource {
	return &staticGraphSource{byTenant: map[string]*graph.Graph{}, wmByTen: map[string]string{}}
}

func (s *staticGraphSource) set(tenantID string, g *graph.Graph, watermark string) {
	s.byTenant[tenantID] = g
	s.wmByTen[tenantID] = watermark
}

func (s *staticGraphSource) GraphForTenant(_ context.Context, tenantID string) (*graph.Graph, string, error) {
	g, ok := s.byTenant[tenantID]
	if !ok {
		return graph.New(), s.wmByTen[tenantID], nil
	}
	return g, s.wmByTen[tenantID], nil
}

// fixtureGraph builds a small labeled credential graph the reachability tests resolve
// against. Shape (impact flows From→To, so a node's forward-reachable set is what it can
// reach):
//
//	res:svc-payments ──CONNECTS_TO──▶ cred:cert-payments ──DEPLOYED_TO──▶ res:payments-db (confidential)
//	                                  cred:cert-payments ──GRANTS_ACCESS─▶ res:secrets-vault (restricted, prohibited "env=prod")
//	res:svc-web      ──CONNECTS_TO──▶ cred:cert-web      ──DEPLOYED_TO──▶ res:lb-edge (public)
//
// The engine starts the closure from the resource nodes named by an authority's resource
// selectors (res:svc-payments / res:svc-web / ...), so seeding those service nodes as the
// authority's ResourceValues drives a real bounded walk to the assets they front.
func fixtureGraph() *graph.Graph {
	g := graph.New()
	nodes := []graph.Node{
		{ID: "res:svc-payments", Kind: graph.KindResource, Name: "payments-service"},
		{ID: "res:svc-web", Kind: graph.KindResource, Name: "web-service"},
		{ID: "cred:cert-payments", Kind: graph.KindCredential, Name: "payments.example"},
		{ID: "cred:cert-web", Kind: graph.KindCredential, Name: "web.example"},
		{ID: "res:payments-db", Kind: graph.KindResource, Name: "payments-db", Attrs: map[string]string{"sensitivity": "confidential", "env": "prod"}},
		{ID: "res:secrets-vault", Kind: graph.KindResource, Name: "secrets-vault", Attrs: map[string]string{"sensitivity": "restricted", "env": "prod"}},
		{ID: "res:lb-edge", Kind: graph.KindResource, Name: "lb-edge", Attrs: map[string]string{"sensitivity": "public"}},
	}
	for _, n := range nodes {
		g.AddNode(n)
	}
	edges := []graph.Edge{
		{From: "res:svc-payments", To: "cred:cert-payments", Type: graph.EdgeConnectsTo},
		{From: "cred:cert-payments", To: "res:payments-db", Type: graph.EdgeDeployedTo},
		{From: "cred:cert-payments", To: "res:secrets-vault", Type: graph.EdgeGrantsAccess},
		{From: "res:svc-web", To: "cred:cert-web", Type: graph.EdgeConnectsTo},
		{From: "cred:cert-web", To: "res:lb-edge", Type: graph.EdgeDeployedTo},
	}
	for _, e := range edges {
		g.AddEdge(e)
	}
	return g
}

// verdictSigner is a software ECDSA verdict signer plus its public DER and a matching trust
// lookup keyed by the key id. It mirrors the delegation package's signerWithDER.
type verdictSigner struct {
	signer crypto.Signer
	keyID  string
	pubDER []byte
}

func newVerdictSigner(t *testing.T, keyID string) verdictSigner {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	s, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate verdict key: %v", err)
	}
	return verdictSigner{signer: s, keyID: keyID, pubDER: s.Public().DER}
}

// keyRef is the verdict key reference for this signer.
func (v verdictSigner) keyRef() reach.VerdictKeyRef {
	return reach.VerdictKeyRef{ID: v.keyID, Algorithm: string(crypto.ECDSAP256)}
}

// trust returns a reach.VerdictTrustLookup that trusts exactly this signer's key id.
func (v verdictSigner) trust() reach.VerdictTrustLookup {
	return func(id string) ([]byte, bool) {
		if id == v.keyID {
			return v.pubDER, true
		}
		return nil, false
	}
}

// paymentsRequest is the standard authority request the tests use: it fronts the payments
// service (whose closure reaches the confidential db and the restricted vault) for tenant t.
func paymentsRequest(tenantID string) engine.AuthorityRequest {
	return engine.AuthorityRequest{TenantID: tenantID, ResourceValues: []string{"svc-payments"}}
}

// nodeWithSensitivity builds a resource node carrying a sensitivity label, for cache tests.
func nodeWithSensitivity(id, sensitivity string) graph.Node {
	return graph.Node{ID: id, Kind: graph.KindResource, Name: id, Attrs: map[string]string{"sensitivity": sensitivity}}
}

// edge builds a CONNECTS_TO-style DEPLOYED_TO edge between two nodes for cache tests.
func edge(from, to string) graph.Edge {
	return graph.Edge{From: from, To: to, Type: graph.EdgeDeployedTo}
}
