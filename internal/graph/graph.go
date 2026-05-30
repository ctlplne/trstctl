package graph

import "sort"

// NodeKind classifies a graph node. The inventory is modeled as workloads, the
// identities/credentials issued to them, the issuers that signed those
// credentials, and the resources the credentials reach (F21).
type NodeKind string

const (
	KindWorkload   NodeKind = "workload"   // a non-human principal (service, agent, app)
	KindCredential NodeKind = "credential" // a certificate, SSH key, secret, or token
	KindResource   NodeKind = "resource"   // a place a credential is deployed to or grants access to
	KindIssuer     NodeKind = "issuer"     // a CA or other authority that issues credentials
)

// EdgeType names a directed relationship. Direction is oriented so that impact
// flows From→To: compromising the From node puts the To node at risk. A node's
// forward-reachable set is therefore its blast radius.
type EdgeType string

const (
	EdgeIssued       EdgeType = "ISSUED"        // issuer → credential it signed
	EdgeOwns         EdgeType = "OWNS"          // workload → credential it holds/uses
	EdgeDeployedTo   EdgeType = "DEPLOYED_TO"   // credential → resource it is installed on
	EdgeGrantsAccess EdgeType = "GRANTS_ACCESS" // credential → resource it can authenticate to
	EdgeConnectsTo   EdgeType = "CONNECTS_TO"   // workload/resource → workload it talks to
)

// Node is a vertex in the credential graph. ID is the stable, unique key;
// Attrs carries non-indexed metadata (e.g. fingerprint, status, expiry) that
// Cypher WHERE clauses can filter on.
type Node struct {
	ID    string            `json:"id"`
	Kind  NodeKind          `json:"kind"`
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Type EdgeType `json:"type"`
}

// Graph is an in-memory directed multigraph of the inventory. It is built once
// per query (cheaply, from the tenant's inventory) and is not safe for
// concurrent mutation; queries over a built graph are read-only.
type Graph struct {
	nodes map[string]Node
	out   map[string][]Edge // adjacency by source node ID
	edges []Edge            // insertion-deduplicated edge list
	seen  map[string]bool   // dedup key "From|Type|To"
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]Node{},
		out:   map[string][]Edge{},
		seen:  map[string]bool{},
	}
}

// AddNode inserts or replaces a node keyed by ID. It is idempotent.
func (g *Graph) AddNode(n Node) { g.nodes[n.ID] = n }

// AddEdge inserts a directed edge. Duplicate (From,Type,To) edges are ignored,
// so building from an inventory that mentions a relationship twice is safe.
func (g *Graph) AddEdge(e Edge) {
	key := e.From + "|" + string(e.Type) + "|" + e.To
	if g.seen[key] {
		return
	}
	g.seen[key] = true
	g.edges = append(g.edges, e)
	g.out[e.From] = append(g.out[e.From], e)
}

// Node returns the node with the given ID.
func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// Order is the number of nodes.
func (g *Graph) Order() int { return len(g.nodes) }

// Size is the number of distinct edges.
func (g *Graph) Size() int { return len(g.edges) }

// Nodes returns every node, sorted by ID.
func (g *Graph) Nodes() []Node {
	out := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Edges returns every edge in insertion order.
func (g *Graph) Edges() []Edge {
	out := make([]Edge, len(g.edges))
	copy(out, g.edges)
	return out
}

// allows reports whether an edge of type t is permitted by the (possibly empty)
// type filter. An empty filter permits every type.
func allows(types []EdgeType, t EdgeType) bool {
	if len(types) == 0 {
		return true
	}
	for _, want := range types {
		if want == t {
			return true
		}
	}
	return false
}

// Neighbors returns the direct out-neighbors of a node, optionally restricted to
// the given edge types. Results are existing nodes only, sorted by ID.
func (g *Graph) Neighbors(id string, types ...EdgeType) []Node {
	var out []Node
	seen := map[string]bool{}
	for _, e := range g.out[id] {
		if !allows(types, e.Type) || seen[e.To] {
			continue
		}
		if n, ok := g.nodes[e.To]; ok {
			seen[e.To] = true
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Reachable returns every node reachable from the start node by following
// out-edges transitively, excluding the start node itself. With one or more
// edge types it follows only those types. Results are sorted by ID.
func (g *Graph) Reachable(from string, types ...EdgeType) []Node {
	visited := map[string]bool{from: true}
	queue := []string{from}
	var out []Node
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.out[cur] {
			if !allows(types, e.Type) || visited[e.To] {
				continue
			}
			visited[e.To] = true
			if n, ok := g.nodes[e.To]; ok {
				out = append(out, n)
				queue = append(queue, e.To)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Reaches reports whether to is forward-reachable from from. A node does not
// reach itself.
func (g *Graph) Reaches(from, to string) bool {
	if from == to {
		return false
	}
	for _, n := range g.Reachable(from) {
		if n.ID == to {
			return true
		}
	}
	return false
}

// Impact is the result of a blast-radius query: every node affected if Node is
// compromised, both as a flat list and grouped by kind.
type Impact struct {
	Node     Node                `json:"node"`
	Affected []Node              `json:"affected"`
	ByKind   map[NodeKind][]Node `json:"by_kind"`
}

// BlastRadius computes the impact of compromising the given node: its full
// forward-reachable set (the downstream credentials, resources, and workloads
// put at risk), grouped by kind. The node itself is recorded in Impact.Node and
// excluded from the affected set.
func (g *Graph) BlastRadius(id string) Impact {
	imp := Impact{ByKind: map[NodeKind][]Node{}}
	if n, ok := g.nodes[id]; ok {
		imp.Node = n
	}
	imp.Affected = g.Reachable(id)
	for _, n := range imp.Affected {
		imp.ByKind[n.Kind] = append(imp.ByKind[n.Kind], n)
	}
	return imp
}
