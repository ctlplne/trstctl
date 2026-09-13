// SPDX-License-Identifier: MPL-2.0

package graph

import "sort"

// NodeKind classifies a graph node. The inventory is modeled as workloads, the
// identities/credentials issued to them, the issuers that signed those
// credentials, and the resources the credentials reach (F21).
type NodeKind string

const (
	KindWorkload    NodeKind = "workload"     // a non-human principal (service, agent, app)
	KindCredential  NodeKind = "credential"   // a certificate, SSH key, secret, or token
	KindResource    NodeKind = "resource"     // a place a credential is deployed to or grants access to
	KindIssuer      NodeKind = "issuer"       // a CA or other authority that issues credentials
	KindCryptoAsset NodeKind = "crypto-asset" // an observed cryptographic usage (CBOM, F52)
	KindAttestation NodeKind = "attestation"  // a verified proof (hardware/cloud/platform) that justified an issuance (F30)
	// KindTrustStore is a discovered trust store — an OS/Java/NSS/browser
	// anchor set on some host (epic H1).
	//
	// A store is a node rather than an attribute on the host because the same
	// machine routinely carries several with DIFFERENT contents: the OS store,
	// a JVM's cacerts, Firefox's NSS DB. "Is this CA trusted on host X" has no
	// single answer, and modelling the store as a property of the host would
	// force one.
	KindTrustStore NodeKind = "trust-store"
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
	EdgeConnectsTo   EdgeType = "CONNECTS_TO"   // workload/resource → resource/workload it talks to
	// A retained certificate fact belongs to an exact lifecycle identity.
	// This historical binding does not assert what a listener is serving now.
	EdgeBoundToIdentity EdgeType = "BOUND_TO_IDENTITY"
	EdgeExhibits        EdgeType = "EXHIBITS" // resource → crypto asset it exhibits (CBOM, F52)
	// EdgeTrusts is trust-store → issuer whose anchor it contains (epic H1).
	//
	// Oriented store → issuer, matching the direction convention: an edge points
	// the way IMPACT travels. A compromised or rotated CA propagates to every
	// store holding its anchor, so following the graph outward from an issuer
	// answers "who breaks if this changes" — which is the question a rollover
	// or an incident actually asks.
	EdgeTrusts EdgeType = "TRUSTS"
	// EdgeTrustCandidate is a subject-only issuer correlation. It is visible in
	// graph/API/console evidence but excluded from default traversal and every
	// authoritative trust count. Callers must ask for this edge type explicitly.
	EdgeTrustCandidate EdgeType = "UNVERIFIED_TRUST_CANDIDATE"
	// EdgeHosts is resource → trust store located on it (epic H1).
	//
	// It is what turns "N stores" into "N stores across M hosts". Without it a
	// trust store would float free of the machine that has it, and the answer to
	// "where do I go to fix this" would be missing.
	EdgeHosts EdgeType = "HOSTS"
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

// Edge is a directed relationship between two nodes. Source tells an operator
// which tenant-scoped record produced the relationship; Confidence states how
// strongly that record establishes the link. Both are evidence labels, not
// authorization inputs, and are optional for backward compatibility with graph
// fixtures and callers that construct an in-memory graph directly.
type Edge struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Type       EdgeType `json:"type"`
	Source     string   `json:"source,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
}

// EvidencePath is one deterministic, shortest, server-owned explanation for
// how a starting node reaches Target. Nodes includes both endpoints in travel
// order; Edges contains the relationship between each adjacent node pair.
// Returning the chain keeps consoles and SDKs from inventing risk paths from a
// flat affected-node list.
type EvidencePath struct {
	Target Node   `json:"target"`
	Nodes  []Node `json:"nodes"`
	Edges  []Edge `json:"edges"`
}

// Graph is an in-memory directed multigraph of the inventory. It is built once
// per query (cheaply, from the tenant's inventory) and is not safe for
// concurrent mutation; queries over a built graph are read-only.
type Graph struct {
	nodes map[string]Node
	out   map[string][]Edge // adjacency by source node ID
	in    map[string][]Edge // reverse adjacency by destination node ID
	edges []Edge            // insertion-deduplicated edge list
	seen  map[string]bool   // dedup key "From|Type|To"
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]Node{},
		out:   map[string][]Edge{},
		in:    map[string][]Edge{},
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
	g.in[e.To] = append(g.in[e.To], e)
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
// type filter. An empty filter permits every authoritative type; an unverified
// candidate must be requested explicitly so default blast-radius traversal cannot
// turn a display-name similarity into an automation input.
func allows(types []EdgeType, t EdgeType) bool {
	if len(types) == 0 {
		return t != EdgeTrustCandidate
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

// IncomingNeighbors returns the direct predecessors of a node, optionally
// restricted to edge types. Production OWNS points workload → credential, so
// asking who owns a credential is an incoming-edge question. Keeping the
// reverse index beside the forward adjacency prevents consumers from reversing
// production edges in fixtures just to make attribution appear to work.
func (g *Graph) IncomingNeighbors(id string, types ...EdgeType) []Node {
	var out []Node
	seen := map[string]bool{}
	for _, e := range g.in[id] {
		if !allows(types, e.Type) || seen[e.From] {
			continue
		}
		if n, ok := g.nodes[e.From]; ok {
			seen[e.From] = true
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// EvidencePaths returns one shortest path from from to every reachable node.
// Outgoing choices are sorted before breadth-first traversal, so equal-length
// alternatives produce stable evidence across rebuilds. Unverified trust
// candidates remain excluded unless the caller explicitly requests that type.
func (g *Graph) EvidencePaths(from string, types ...EdgeType) []EvidencePath {
	paths := make([]EvidencePath, 0)
	if _, ok := g.nodes[from]; !ok {
		return paths
	}

	visited := map[string]bool{from: true}
	queue := []string{from}
	predecessor := map[string]Edge{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		outgoing := append([]Edge(nil), g.out[cur]...)
		sort.Slice(outgoing, func(i, j int) bool {
			if outgoing[i].To != outgoing[j].To {
				return outgoing[i].To < outgoing[j].To
			}
			if outgoing[i].Type != outgoing[j].Type {
				return outgoing[i].Type < outgoing[j].Type
			}
			if outgoing[i].Source != outgoing[j].Source {
				return outgoing[i].Source < outgoing[j].Source
			}
			return outgoing[i].Confidence < outgoing[j].Confidence
		})
		for _, e := range outgoing {
			if !allows(types, e.Type) || visited[e.To] {
				continue
			}
			if _, ok := g.nodes[e.To]; !ok {
				continue
			}
			visited[e.To] = true
			predecessor[e.To] = e
			queue = append(queue, e.To)
		}
	}

	targetIDs := make([]string, 0, len(predecessor))
	for id := range predecessor {
		targetIDs = append(targetIDs, id)
	}
	sort.Strings(targetIDs)
	for _, targetID := range targetIDs {
		reverseNodes := []Node{g.nodes[targetID]}
		var reverseEdges []Edge
		for cursor := targetID; cursor != from; {
			edge := predecessor[cursor]
			reverseEdges = append(reverseEdges, edge)
			reverseNodes = append(reverseNodes, g.nodes[edge.From])
			cursor = edge.From
		}
		reverseNodesInPlace(reverseNodes)
		reverseEdgesInPlace(reverseEdges)
		paths = append(paths, EvidencePath{Target: g.nodes[targetID], Nodes: reverseNodes, Edges: reverseEdges})
	}
	return paths
}

// Reachable returns every node reachable from the start node by following
// out-edges transitively, excluding the start node itself. With one or more
// edge types it follows only those types. Results are sorted by ID.
func (g *Graph) Reachable(from string, types ...EdgeType) []Node {
	paths := g.EvidencePaths(from, types...)
	out := make([]Node, 0, len(paths))
	for _, path := range paths {
		out = append(out, path.Target)
	}
	return out
}

func reverseNodesInPlace(nodes []Node) {
	for left, right := 0, len(nodes)-1; left < right; left, right = left+1, right-1 {
		nodes[left], nodes[right] = nodes[right], nodes[left]
	}
}

func reverseEdgesInPlace(edges []Edge) {
	for left, right := 0, len(edges)-1; left < right; left, right = left+1, right-1 {
		edges[left], edges[right] = edges[right], edges[left]
	}
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
	Paths    []EvidencePath      `json:"paths"`
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
	imp.Paths = g.EvidencePaths(id)
	imp.Affected = make([]Node, 0, len(imp.Paths))
	for _, path := range imp.Paths {
		imp.Affected = append(imp.Affected, path.Target)
	}
	// A leaf has a real, successful answer: zero known affected nodes. Encode
	// that as [] instead of JSON null so every API client can iterate the result
	// without turning an ordinary zero-edge credential into a page crash.
	if imp.Affected == nil {
		imp.Affected = []Node{}
	}
	for _, n := range imp.Affected {
		imp.ByKind[n.Kind] = append(imp.ByKind[n.Kind], n)
	}
	return imp
}
