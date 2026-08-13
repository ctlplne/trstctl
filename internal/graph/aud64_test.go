// SPDX-License-Identifier: MPL-2.0

package graph

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestAUD64ServiceDependencyFindingFailsClosed(t *testing.T) {
	t.Parallel()
	base := store.DiscoveryFinding{
		ID:       "finding-a",
		Kind:     serviceDependencyFindingKind,
		Ref:      "lb-edge",
		Metadata: json.RawMessage(`{"workload":"checkout-service","target":"lb-edge","protocol":"https"}`),
	}
	for name, mutate := range map[string]func(*store.DiscoveryFinding){
		"malformed metadata": func(f *store.DiscoveryFinding) { f.Metadata = json.RawMessage(`{`) },
		"missing workload":   func(f *store.DiscoveryFinding) { f.Metadata = json.RawMessage(`{"target":"lb-edge"}`) },
		"mismatched target": func(f *store.DiscoveryFinding) {
			f.Metadata = json.RawMessage(`{"workload":"checkout-service","target":"other"}`)
		},
		"unmapped workload": func(f *store.DiscoveryFinding) {
			f.Metadata = json.RawMessage(`{"workload":"missing","target":"lb-edge"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			finding := base
			mutate(&finding)
			if handled, err := addServiceDependencyFinding(New(), finding, map[string]string{"checkout-service": "owner-a"}); !handled || err == nil {
				t.Fatalf("handled=%t err=%v, want handled fail-closed error", handled, err)
			}
		})
	}
	if handled, err := addServiceDependencyFinding(New(), base, map[string]string{"checkout-service": ""}); !handled || err == nil {
		t.Fatalf("ambiguous workload handled=%t err=%v, want handled fail-closed error", handled, err)
	}

	g := New()
	g.AddNode(Node{ID: "wl:owner-a", Kind: KindWorkload, Name: "checkout-service"})
	handled, err := addServiceDependencyFinding(g, base, map[string]string{"checkout-service": "owner-a"})
	if err != nil || !handled {
		t.Fatalf("valid service dependency handled=%t err=%v", handled, err)
	}
	neighbors := g.Neighbors("wl:owner-a", EdgeConnectsTo)
	if len(neighbors) != 1 || neighbors[0].ID != "res:lb-edge" {
		t.Fatalf("CONNECTS_TO neighbors = %+v, want lb-edge", neighbors)
	}
}

func TestAUD64IncomingOwnerTraversalMatchesProductionDirection(t *testing.T) {
	t.Parallel()
	g := New()
	g.AddNode(Node{ID: "wl:owner-a", Kind: KindWorkload, Name: "payments-team"})
	g.AddNode(Node{ID: "cred:a", Kind: KindCredential, Name: "payments-cert"})
	g.AddEdge(Edge{From: "wl:owner-a", To: "cred:a", Type: EdgeOwns})
	owners := g.IncomingNeighbors("cred:a", EdgeOwns)
	if len(owners) != 1 || owners[0].ID != "wl:owner-a" {
		t.Fatalf("incoming owners = %+v, want workload owner", owners)
	}
	if reversed := g.Neighbors("cred:a", EdgeOwns); len(reversed) != 0 {
		t.Fatalf("credential has reversed outgoing OWNS neighbors: %+v", reversed)
	}
}
