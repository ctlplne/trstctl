// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reach

import (
	"bytes"
	"context"
	"testing"
)

// TestEngine_ResolveComputesBoundedReachableSet checks the engine resolves the requested
// authority to the correct reachable set: it starts the closure from the resource nodes
// named by the authority's resource selectors, walks the bounded forward closure, and
// classifies cardinality, sensitivity, and present labels from the graph.
func TestEngine_ResolveComputesBoundedReachableSet(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := NewEngine(src)

	set, wm, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if wm != "wm-1" {
		t.Fatalf("watermark = %q, want wm-1", wm)
	}
	// From res:svc-payments the closure reaches: cred:cert-payments, res:payments-db,
	// res:secrets-vault (3 nodes; the start node itself is excluded).
	wantIDs := map[string]bool{"cred:cert-payments": true, "res:payments-db": true, "res:secrets-vault": true}
	if set.Cardinality != len(wantIDs) {
		t.Fatalf("cardinality = %d, want %d (nodes: %+v)", set.Cardinality, len(wantIDs), ids(set))
	}
	for _, n := range set.Nodes {
		if !wantIDs[n.ID] {
			t.Errorf("unexpected reachable node %q", n.ID)
		}
	}
	// The most sensitive reachable asset is the restricted secrets-vault.
	if set.MaxSensitivity != SensitivityRestricted {
		t.Errorf("MaxSensitivity = %s, want restricted", set.MaxSensitivity)
	}
	if set.TenantSpan != 1 {
		t.Errorf("TenantSpan = %d, want 1 (single-tenant build)", set.TenantSpan)
	}
	// The prohibited-label ("env=prod") must be surfaced in PresentLabels.
	if !containsStr(set.PresentLabels, "env=prod") {
		t.Errorf("PresentLabels %v does not contain env=prod", set.PresentLabels)
	}
}

// TestEngine_StartNodeUnknownIsDropped checks that a resource value naming no graph node
// fronts nothing (refusal-on-computation as of the watermark, not omniscience): the
// reachable set is empty, cardinality 0, span 0.
func TestEngine_StartNodeUnknownIsDropped(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := NewEngine(src)

	set, _, err := e.Resolve(context.Background(), AuthorityRequest{TenantID: tenant, ResourceValues: []string{"does-not-exist"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if set.Cardinality != 0 || set.TenantSpan != 0 {
		t.Fatalf("empty request: cardinality=%d span=%d, want 0/0", set.Cardinality, set.TenantSpan)
	}
	if set.MaxSensitivity != SensitivityUnknown {
		t.Fatalf("empty set MaxSensitivity = %s, want unknown", set.MaxSensitivity)
	}
}

// TestEngine_DepthBoundLimitsClosure checks the closure is bounded: at depth 1 from the
// service, only the directly-connected credential is reachable (not the assets one further
// hop away).
func TestEngine_DepthBoundLimitsClosure(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := NewEngine(src, WithMaxDepth(1))

	set, _, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Depth 1 reaches only cred:cert-payments (the assets it fronts are at depth 2).
	if set.Cardinality != 1 || set.Nodes[0].ID != "cred:cert-payments" {
		t.Fatalf("depth-1 closure = %+v, want just cred:cert-payments", ids(set))
	}
}

// TestReachableSetDigest_DeterministicForFixedWatermark is the PROPERTY test the card
// requires: for a fixed graph watermark the reachable-set digest is identical across
// repeated resolutions (so a verdict's bound digest is reproducible). It resolves twice
// and compares digests; it also constructs the same logical set with nodes added in a
// different order to prove the canonical (sorted) encoding is order-independent.
func TestReachableSetDigest_DeterministicForFixedWatermark(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := NewEngine(src)

	setA, _, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve A: %v", err)
	}
	setB, _, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve B: %v", err)
	}
	if !bytes.Equal(setA.Digest(), setB.Digest()) {
		t.Fatalf("reachable-set digest not deterministic for fixed watermark:\n A=%x\n B=%x", setA.Digest(), setB.Digest())
	}

	// Order-independence: shuffle the node slice and recompute; the canonical encoding
	// sorts, so the digest is unchanged.
	shuffled := ReachableSet{TenantID: setA.TenantID, Cardinality: setA.Cardinality, MaxSensitivity: setA.MaxSensitivity, TenantSpan: setA.TenantSpan, PresentLabels: setA.PresentLabels}
	for i := len(setA.Nodes) - 1; i >= 0; i-- {
		shuffled.Nodes = append(shuffled.Nodes, setA.Nodes[i])
	}
	if !bytes.Equal(setA.Digest(), shuffled.Digest()) {
		t.Fatalf("reachable-set digest changed under node reordering (canonical encoding must be order-independent)")
	}
}

// TestEngine_WatermarkCacheReusesGeneration checks the per-tenant watermark cache: two
// resolutions at the SAME watermark reuse one graph generation (identical digest), and a
// NEW watermark after the graph changes yields a fresh generation (the digest reflects the
// change). This exercises the on-demand-build + watermark-cache design without a persisted
// store.
func TestEngine_WatermarkCacheReusesGeneration(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := NewEngine(src)

	set1, wm1, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve 1: %v", err)
	}
	if wm1 != "wm-1" {
		t.Fatalf("wm1 = %q", wm1)
	}

	// Mutate the underlying graph but KEEP the watermark: the engine must reuse the cached
	// generation for wm-1 (digest unchanged), proving freshness is bounded by the watermark.
	g2 := fixtureGraph()
	g2.AddNode(nodeWithSensitivity("res:extra", "restricted"))
	g2.AddEdge(edge("cred:cert-payments", "res:extra"))
	src.set(tenant, g2, "wm-1") // same watermark, different graph
	set2, _, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve 2: %v", err)
	}
	if !bytes.Equal(set1.Digest(), set2.Digest()) {
		t.Fatalf("same-watermark resolution changed digest; cache must reuse the generation")
	}

	// Now bump the watermark: the engine rebuilds and the new node appears.
	src.set(tenant, g2, "wm-2")
	set3, wm3, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve 3: %v", err)
	}
	if wm3 != "wm-2" {
		t.Fatalf("wm3 = %q, want wm-2", wm3)
	}
	if set3.Cardinality != set1.Cardinality+1 {
		t.Fatalf("new-watermark cardinality = %d, want %d (the extra node must appear)", set3.Cardinality, set1.Cardinality+1)
	}
	if bytes.Equal(set1.Digest(), set3.Digest()) {
		t.Fatalf("new-watermark digest must differ once the graph changed")
	}
}

// ---- small helpers ----

func ids(s ReachableSet) []string {
	out := make([]string, len(s.Nodes))
	for i, n := range s.Nodes {
		out[i] = n.ID
	}
	return out
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
