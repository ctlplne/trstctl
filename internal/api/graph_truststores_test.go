// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/graph"
)

// The trust query's shape and its refusals (epic H1).
//
// The interesting behavior is not the happy path — it is what the surface says
// when it has nothing to say. "No store trusts this CA" and "you asked about
// something that is not a CA" are different statements, and during a rollover
// the first one read wrongly is how a root gets retired out from under a fleet.

func TestTrustStoreCountsDistinguishStoresFromHosts(t *testing.T) {
	t.Parallel()
	g := graph.New()
	issuer := "iss:ca-1"
	g.AddNode(graph.Node{ID: issuer, Kind: graph.KindIssuer, Name: "Corp Root CA"})

	// Two stores on one host, one store on another: three stores, two machines.
	for _, s := range []struct{ id, host string }{
		{"ts:web01:os", "web01"},
		{"ts:web01:java-cacerts", "web01"},
		{"ts:web02:os", "web02"},
	} {
		g.AddNode(graph.Node{
			ID: s.id, Kind: graph.KindTrustStore, Name: s.id,
			Attrs: map[string]string{"host": s.host},
		})
		g.AddNode(graph.Node{ID: "res:" + s.host, Kind: graph.KindResource, Name: s.host})
		g.AddEdge(graph.Edge{From: s.id, To: issuer, Type: graph.EdgeTrusts})
	}

	stores, hosts := g.TrustStoresForIssuer(issuer)
	if len(stores) != 3 {
		t.Errorf("stores = %d, want 3", len(stores))
	}
	if len(hosts) != 2 {
		t.Errorf("hosts = %d, want 2; the headline is 'N stores across M hosts' and collapsing "+
			"them would tell an operator to visit one machine when two are affected", len(hosts))
	}
}

// A CA nothing has been observed trusting reports zero — and the guidance says
// that means unobserved, not absent.
func TestAnUnobservedCAReportsZeroWithAnHonestExplanation(t *testing.T) {
	t.Parallel()
	g := graph.New()
	g.AddNode(graph.Node{ID: "iss:lonely", Kind: graph.KindIssuer, Name: "Unused CA"})

	stores, hosts := g.TrustStoresForIssuer("iss:lonely")
	if len(stores) != 0 || len(hosts) != 0 {
		t.Fatalf("stores=%d hosts=%d, want 0 and 0", len(stores), len(hosts))
	}
	// The served guidance has to close the gap between "we found none" and
	// "there are none", because acting on the second when you have the first is
	// how a root gets retired out from under a fleet nobody scanned.
	guidance := trustStoreGuidanceForCounts(0, 0)
	for _, phrase := range []string{"0 unverified subject-only candidate stores across 0 hosts", "observed", "not what exists", "exact certificate", "SPKI SHA-256", "unverified candidate", "excluded from counts and automation"} {
		if !contains(guidance, phrase) {
			t.Errorf("the trust-store guidance does not say %q; a zero would read as proof that "+
				"nothing trusts this CA", phrase)
		}
	}
}

func TestTrustStoreGuidanceSeparatesCandidateCounts(t *testing.T) {
	t.Parallel()
	guidance := trustStoreGuidanceForCounts(3, 2)
	if !contains(guidance, "3 unverified subject-only candidate stores across 2 hosts") {
		t.Fatalf("candidate guidance did not preserve separate store/host counts: %q", guidance)
	}
}

// Edges pointing at OTHER issuers must not be counted.
func TestOnlyStoresTrustingTheNamedIssuerAreCounted(t *testing.T) {
	t.Parallel()
	g := graph.New()
	g.AddNode(graph.Node{ID: "iss:a", Kind: graph.KindIssuer, Name: "CA A"})
	g.AddNode(graph.Node{ID: "iss:b", Kind: graph.KindIssuer, Name: "CA B"})
	g.AddNode(graph.Node{ID: "ts:h:os", Kind: graph.KindTrustStore, Name: "os",
		Attrs: map[string]string{"host": "h"}})
	g.AddNode(graph.Node{ID: "res:h", Kind: graph.KindResource, Name: "h"})
	g.AddEdge(graph.Edge{From: "ts:h:os", To: "iss:b", Type: graph.EdgeTrusts})

	if stores, _ := g.TrustStoresForIssuer("iss:a"); len(stores) != 0 {
		t.Errorf("a store trusting CA B was counted for CA A (%d stores); the blast radius of a "+
			"rollover would include machines it does not touch", len(stores))
	}
	if stores, _ := g.TrustStoresForIssuer("iss:b"); len(stores) != 1 {
		t.Error("the store trusting CA B was not counted for CA B")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && stringsContains(haystack, needle)
}

func stringsContains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
