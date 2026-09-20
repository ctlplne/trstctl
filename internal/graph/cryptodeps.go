// SPDX-License-Identifier: BUSL-1.1

package graph

import "sort"

// Crypto dependency edges and readiness sequencing (epic M2).
//
// The CBOM already answers "where is weak crypto", and the graph already holds
// each observed usage as a crypto-asset node linked to the resource that
// exhibits it. What neither answers is the question an operator actually has to
// act on: if I retire this algorithm, WHO BREAKS?
//
// Without that, a migration is sequenced by severity alone, which sorts a
// forgotten lab box exhibiting RSA-1024 above a load balancer twelve services
// authenticate through. Severity says which crypto is worst; only dependency
// says which change is hardest and which is urgent.
//
// The traversal is deliberately shallow and explainable. From a crypto asset it
// walks BACK along EXHIBITS to the resources that exhibit it, then BACK again
// along the dependency edges to the parties that depend on those resources —
// both hops are reverse, because every edge involved points from the dependent
// toward the thing depended on. Every dependent carries the resource it was
// reached through, because a sequencing recommendation nobody can check is one
// nobody should act on.

// cryptoDependencyEdges are the ways a party can depend on a resource.
//
// All three are followed in REVERSE, and getting that wrong is the easy mistake
// here: every one of them points FROM the dependent TO the resource. A workload
// CONNECTS_TO the load balancer; a credential is DEPLOYED_TO it and
// GRANTS_ACCESS to it. Walking out-edges from the resource therefore finds
// nothing at all, and a readiness table built that way reports zero dependents
// for everything while looking perfectly well-formed — the worst possible
// failure for a surface whose entire job is counting dependents.
var cryptoDependencyEdges = []EdgeType{EdgeConnectsTo, EdgeGrantsAccess, EdgeDeployedTo}

// CryptoDependent is one party that depends on a crypto asset, and the resource
// the dependency runs through.
type CryptoDependent struct {
	Node Node   `json:"node"`
	Via  Node   `json:"via"`
	Edge string `json:"edge"`
}

// CryptoReadinessRow is one crypto asset with everything needed to sequence it.
type CryptoReadinessRow struct {
	Asset Node `json:"asset"`
	// Exhibitors are the resources observed using this crypto.
	Exhibitors []Node `json:"exhibitors"`
	// Dependents are the parties that depend on those resources.
	Dependents []CryptoDependent `json:"dependents"`
	// Owners are the owning principals of the dependents, for attribution.
	Owners []string `json:"owners"`
	// QuantumVulnerable and OutOfPolicy come from the CBOM observation.
	QuantumVulnerable bool `json:"quantum_vulnerable"`
	OutOfPolicy       bool `json:"out_of_policy"`
	// Unlocated is true when the CBOM recorded this usage with no location, so
	// it has NO exhibitor edge and cannot be sequenced at all.
	//
	// Reported rather than dropped. An asset that cannot be placed is not a
	// low-risk asset; it is one whose blast radius is unknown, and silently
	// omitting it from a readiness table would make the table look complete.
	Unlocated bool `json:"unlocated"`
	// Recommendation is the sequencing sentence for this row.
	Recommendation string `json:"recommendation"`
}

// CryptoReadiness sequences every crypto asset by dependency and exposure.
//
// Sorted worst-first: vulnerable-or-out-of-policy before compliant, then by
// how many parties depend on it, then by ID so the order is stable across
// calls. An operator reading top-down is reading the order the migration should
// actually happen in.
func (g *Graph) CryptoReadiness() []CryptoReadinessRow {
	// EXHIBITS runs resource → asset, so finding an asset's exhibitors needs the
	// reverse direction. Built once for the whole report rather than rescanned
	// per asset.
	exhibitedBy := map[string][]Node{}
	for _, e := range g.edges {
		if e.Type != EdgeExhibits {
			continue
		}
		if from, ok := g.nodes[e.From]; ok {
			exhibitedBy[e.To] = append(exhibitedBy[e.To], from)
		}
	}
	// Reverse index: dependent → resource, for every dependency edge type.
	dependsOn := map[string][]Edge{}
	for _, e := range g.edges {
		if allows(cryptoDependencyEdges, e.Type) {
			dependsOn[e.To] = append(dependsOn[e.To], e)
		}
	}

	var rows []CryptoReadinessRow
	for _, n := range g.Nodes() {
		if n.Kind != KindCryptoAsset {
			continue
		}
		row := CryptoReadinessRow{
			Asset:             n,
			QuantumVulnerable: n.Attrs["quantum_vulnerable"] == "true",
			OutOfPolicy:       n.Attrs["out_of_policy"] == "true",
		}
		row.Exhibitors = append(row.Exhibitors, exhibitedBy[n.ID]...)
		sortNodesByID(row.Exhibitors)
		row.Unlocated = len(row.Exhibitors) == 0

		seen := map[string]bool{n.ID: true}
		for _, res := range row.Exhibitors {
			seen[res.ID] = true
		}
		for _, res := range row.Exhibitors {
			for _, e := range dependsOn[res.ID] {
				if seen[e.From] {
					continue
				}
				if dep, ok := g.nodes[e.From]; ok {
					seen[e.From] = true
					row.Dependents = append(row.Dependents, CryptoDependent{Node: dep, Via: res, Edge: string(e.Type)})
				}
			}
		}
		sort.Slice(row.Dependents, func(i, j int) bool { return row.Dependents[i].Node.ID < row.Dependents[j].Node.ID })
		row.Owners = cryptoOwners(g, row.Dependents)
		row.Recommendation = cryptoRecommendation(row)
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ua, ub := cryptoUrgent(a), cryptoUrgent(b); ua != ub {
			return ua
		}
		if len(a.Dependents) != len(b.Dependents) {
			return len(a.Dependents) > len(b.Dependents)
		}
		return a.Asset.ID < b.Asset.ID
	})
	return rows
}

func cryptoUrgent(r CryptoReadinessRow) bool { return r.QuantumVulnerable || r.OutOfPolicy }

// cryptoOwners walks each dependent to the workload that owns it, so a blocker
// has somebody's name on it rather than a node ID.
func cryptoOwners(g *Graph, deps []CryptoDependent) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range deps {
		if d.Node.Kind == KindWorkload {
			if !seen[d.Node.Name] && d.Node.Name != "" {
				seen[d.Node.Name] = true
				out = append(out, d.Node.Name)
			}
			continue
		}
		// Production Build emits OWNS as workload → credential. Attribution
		// therefore walks the credential's incoming OWNS edges; using Neighbors
		// here made the old unit fixture reverse the relationship and hid that the
		// served graph could never recover an actual credential owner.
		for _, owner := range g.IncomingNeighbors(d.Node.ID, EdgeOwns) {
			if owner.Kind == KindWorkload && !seen[owner.Name] && owner.Name != "" {
				seen[owner.Name] = true
				out = append(out, owner.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// cryptoRecommendation says what to do, and refuses to say "safe".
//
// The distinction that matters is between an asset with no OBSERVED dependents
// and an asset with none. The graph is built from discovery, so zero dependents
// means nothing has been seen depending on it — which is exactly what an
// unscanned segment also looks like. Calling that "safe to rotate" would turn a
// coverage gap into a green light, so the wording never does.
func cryptoRecommendation(r CryptoReadinessRow) string {
	switch {
	case r.Unlocated:
		return "The CBOM recorded this usage with no location, so it has no place on the graph and " +
			"its blast radius cannot be computed. Find where it runs before sequencing it — an " +
			"asset that cannot be placed is not a low-risk asset, it is an unmeasured one."
	case len(r.Dependents) == 0 && cryptoUrgent(r):
		return "Weak or quantum-vulnerable, and NO dependent has been observed. That is not the same " +
			"as having none: the graph is built from discovery, so this reads identically to a " +
			"resource nothing has scanned. Confirm coverage of its exhibitors before treating it " +
			"as a low-coordination change."
	case len(r.Dependents) == 0:
		return "No dependent observed. Within the estate discovery has actually covered, retiring " +
			"this breaks nothing known — verify coverage rather than assuming it."
	case cryptoUrgent(r):
		return "Migrate early and coordinate: it is weak or quantum-vulnerable AND carries observed " +
			"dependents, so the change needs scheduling with the owners listed rather than a " +
			"unilateral rotation."
	default:
		return "Compliant today. Sequence after the urgent rows; the dependents listed are who to " +
			"notify when it is rotated."
	}
}
