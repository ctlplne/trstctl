// SPDX-License-Identifier: BUSL-1.1

package graph

import "sort"

// Access questions over the built graph (G1): "who can reach this database?"
// and "how does this person reach it?". Both read the same edges as blast
// radius, walked backward or between two named nodes, so the answer an
// operator gets is the relationship evidence the graph already holds, never a
// list a console assembles on its own.

// AccessLink is one principal tied to a credential, with the edge that ties it:
// its type, the record that produced it and how strongly that record
// establishes it.
type AccessLink struct {
	Node Node `json:"node"`
	Edge Edge `json:"edge"`
}

// AccessGrant is one credential that reaches the target through an access
// grant, the principals that hold it and the people who approved it.
type AccessGrant struct {
	Credential Node `json:"credential"`
	// Grant is the credential's GRANTS_ACCESS edge on its path to the target.
	Grant Edge `json:"grant"`
	// Path runs from the credential to the target.
	Path      EvidencePath `json:"path"`
	Holders   []AccessLink `json:"holders"`
	Approvers []AccessLink `json:"approvers"`
}

// AccessCoverage states which of trstctl's records the access answer is built
// from and what it cannot see, so an empty answer is never read as proof that
// nobody has access.
type AccessCoverage struct {
	Sources    []string `json:"sources"`
	NotCovered []string `json:"not_covered"`
	Note       string   `json:"note"`
}

// ReachersResult answers "who can reach this node?".
type ReachersResult struct {
	Target Node `json:"target"`
	// Reachers is every node whose compromise reaches Target along the graph's
	// impact edges: the reverse of blast radius.
	Reachers []Node              `json:"reachers"`
	ByKind   map[NodeKind][]Node `json:"by_kind"`
	// Paths holds one shortest path per reacher; each starts at the reacher
	// (Nodes[0]) and ends at Target.
	Paths []EvidencePath `json:"paths"`
	// Access lists the credentials that reach Target through an access grant,
	// with who holds each one and who approved it.
	Access   []AccessGrant  `json:"access"`
	Coverage AccessCoverage `json:"coverage"`
}

// Coverage is the fixed statement of what step 1 of the access graph sees.
func Coverage() AccessCoverage {
	return AccessCoverage{
		Sources: []string{
			"tenant members and their roles",
			"API tokens and machine sessions (access to the trstctl API)",
			"PAM sessions to databases and hosts, with the approvals they consumed",
			"dynamic-secret leases",
			"AI agents issued identities by the agent broker",
			"certificate issuance requests and who approved them",
			"the certificate, SSH key, deployment and discovery inventory",
		},
		NotCovered: []string{
			"permissions inside the target system (what a role can do once connected)",
			"who requested a dynamic-secret lease (leases do not record their holder)",
			"access granted outside trstctl",
		},
		Note: "An empty or partial answer is not proof that nobody has access: it covers only access trstctl granted or observed.",
	}
}

// ReverseEvidencePaths returns one shortest path from every node that reaches
// to, each ending at to. Incoming choices are sorted before the breadth-first
// walk, so equal-length alternatives are stable across rebuilds. The type
// filter works as in EvidencePaths.
func (g *Graph) ReverseEvidencePaths(to string, types ...EdgeType) []EvidencePath {
	paths := make([]EvidencePath, 0)
	target, ok := g.nodes[to]
	if !ok {
		return paths
	}
	visited := map[string]bool{to: true}
	queue := []string{to}
	successor := map[string]Edge{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		incoming := append([]Edge(nil), g.in[cur]...)
		sort.Slice(incoming, func(i, j int) bool { return edgeLess(incoming[i], incoming[j]) })
		for _, e := range incoming {
			if !allows(types, e.Type) || visited[e.From] {
				continue
			}
			if _, ok := g.nodes[e.From]; !ok {
				continue
			}
			visited[e.From] = true
			successor[e.From] = e
			queue = append(queue, e.From)
		}
	}
	sources := make([]string, 0, len(successor))
	for id := range successor {
		sources = append(sources, id)
	}
	sort.Strings(sources)
	for _, source := range sources {
		nodes := []Node{g.nodes[source]}
		var edges []Edge
		for cursor := source; cursor != to; {
			edge := successor[cursor]
			edges = append(edges, edge)
			nodes = append(nodes, g.nodes[edge.To])
			cursor = edge.To
		}
		paths = append(paths, EvidencePath{Target: target, Nodes: nodes, Edges: edges})
	}
	return paths
}

// edgeLess orders edges by their far endpoints, type and evidence so
// traversals choose among equal-length alternatives deterministically.
func edgeLess(a, b Edge) bool {
	if a.From != b.From {
		return a.From < b.From
	}
	if a.To != b.To {
		return a.To < b.To
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	return a.Confidence < b.Confidence
}

// PathBetween returns the shortest evidence path from from to to along the
// default impact edges, and false when to is not reachable from from.
func (g *Graph) PathBetween(from, to string) (EvidencePath, bool) {
	if from == to {
		return EvidencePath{}, false
	}
	for _, path := range g.EvidencePaths(from) {
		if path.Target.ID == to {
			return path, true
		}
	}
	return EvidencePath{}, false
}

// WhoCanReach answers "who can reach this node?": every reacher with its path,
// and, for each credential whose path starts with an access grant, the
// principals holding it and the people who approved it. Every link carries the
// source and confidence of the record that produced it.
func (g *Graph) WhoCanReach(id string) ReachersResult {
	out := ReachersResult{
		ByKind: map[NodeKind][]Node{}, Reachers: []Node{}, Access: []AccessGrant{}, Coverage: Coverage(),
	}
	target, ok := g.nodes[id]
	if !ok {
		out.Paths = []EvidencePath{}
		return out
	}
	out.Target = target
	out.Paths = g.ReverseEvidencePaths(id)
	for _, path := range out.Paths {
		reacher := path.Nodes[0]
		out.Reachers = append(out.Reachers, reacher)
		out.ByKind[reacher.Kind] = append(out.ByKind[reacher.Kind], reacher)
		if reacher.Kind != KindCredential || len(path.Edges) == 0 || path.Edges[0].Type != EdgeGrantsAccess {
			continue
		}
		out.Access = append(out.Access, AccessGrant{
			Credential: reacher, Grant: path.Edges[0], Path: path,
			Holders:   g.incomingLinks(reacher.ID, EdgeHolds, EdgeOwns),
			Approvers: g.incomingLinks(reacher.ID, EdgeApproved),
		})
	}
	return out
}

// incomingLinks returns the existing nodes pointing at id over the given edge
// types, each with its edge, ordered by node ID and then edge.
func (g *Graph) incomingLinks(id string, types ...EdgeType) []AccessLink {
	out := []AccessLink{}
	for _, e := range g.in[id] {
		if !allows(types, e.Type) {
			continue
		}
		if n, ok := g.nodes[e.From]; ok {
			out = append(out, AccessLink{Node: n, Edge: e})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Node.ID != out[j].Node.ID {
			return out[i].Node.ID < out[j].Node.ID
		}
		return edgeLess(out[i].Edge, out[j].Edge)
	})
	return out
}
