// SPDX-License-Identifier: BUSL-1.1

package graph_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/graph"
)

func TestCypherHonorsCanceledRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := graph.New().QueryContext(ctx, "MATCH (n) RETURN n"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled graph query returned %v", err)
	}
}

func TestCypherRejectsPathOverEightHops(t *testing.T) {
	g := graph.New()
	query := "MATCH (n0)"
	for i := 1; i <= 9; i++ {
		query += fmt.Sprintf("-[:STEP]->(n%d)", i)
	}
	query += " RETURN n9"
	if _, err := g.Query(query); err == nil || !strings.Contains(err.Error(), "hops") {
		t.Fatalf("nine-hop query must fail at parse time: %v", err)
	}
}

func TestCypherRejectsExplodingPathBindings(t *testing.T) {
	g := graph.New()
	g.AddNode(graph.Node{ID: "root", Kind: graph.KindWorkload})
	previous := []string{"root"}
	for layer := 1; layer <= 4; layer++ {
		current := make([]string, 11)
		for i := range current {
			current[i] = fmt.Sprintf("layer-%d-%d", layer, i)
			g.AddNode(graph.Node{ID: current[i], Kind: graph.KindResource})
			for _, from := range previous {
				g.AddEdge(graph.Edge{From: from, To: current[i], Type: graph.EdgeType("STEP")})
			}
		}
		previous = current
	}
	query := "MATCH (a:workload)-[:STEP]->(b)-[:STEP]->(c)-[:STEP]->(d)-[:STEP]->(e) RETURN a,b,c,d,e"
	if _, err := g.Query(query); err == nil || !strings.Contains(err.Error(), "bindings") {
		t.Fatalf("11^4 path bindings must be rejected before building all result rows: %v", err)
	}
}
