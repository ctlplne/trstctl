// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/graph"
)

// graphResponse is the full credential graph for a tenant.
type graphResponse struct {
	Nodes []graph.Node `json:"nodes"`
	Edges []graph.Edge `json:"edges"`
}

// reachableResponse lists the nodes reachable from a starting node.
type reachableResponse struct {
	From  string       `json:"from"`
	Nodes []graph.Node `json:"nodes"`
}

// queryRequest carries a Cypher-style query.
type queryRequest struct {
	Query string `json:"query"`
}

// queryResponse returns the rows a Cypher-style query produced.
type queryResponse struct {
	Rows []graph.Row `json:"rows"`
}

// getGraph returns the entire credential graph for the tenant, built fresh from
// the inventory (F21).
func (a *API) getGraph(w http.ResponseWriter, r *http.Request) {
	g, tenantOK := a.buildGraph(w, r)
	if !tenantOK {
		return
	}
	a.writeJSON(w, http.StatusOK, graphResponse{Nodes: g.Nodes(), Edges: g.Edges()})
}

// graphReachable answers a reachability query: every node reachable from the
// node named in the path.
func (a *API) graphReachable(w http.ResponseWriter, r *http.Request) {
	g, tenantOK := a.buildGraph(w, r)
	if !tenantOK {
		return
	}
	id := r.PathValue("id")
	if _, ok := g.Node(id); !ok {
		a.writeError(w, errStatus(http.StatusNotFound, "graph node not found"))
		return
	}
	a.writeJSON(w, http.StatusOK, reachableResponse{From: id, Nodes: g.Reachable(id)})
}

// graphBlastRadius answers a blast-radius query: everything affected if the node
// named in the path is compromised.
func (a *API) graphBlastRadius(w http.ResponseWriter, r *http.Request) {
	g, tenantOK := a.buildGraph(w, r)
	if !tenantOK {
		return
	}
	id := r.PathValue("id")
	if _, ok := g.Node(id); !ok {
		a.writeError(w, errStatus(http.StatusNotFound, "graph node not found"))
		return
	}
	a.writeJSON(w, http.StatusOK, g.BlastRadius(id))
}

// graphQuery runs a Cypher-style query against the tenant's graph. It is a
// read; despite being POST (the query travels in the body) it mutates no state.
func (a *API) graphQuery(w http.ResponseWriter, r *http.Request) {
	g, tenantOK := a.buildGraph(w, r)
	if !tenantOK {
		return
	}
	var req queryRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	rows, err := g.Query(req.Query)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	if rows == nil {
		rows = []graph.Row{}
	}
	a.writeJSON(w, http.StatusOK, queryResponse{Rows: rows})
}

// buildGraph resolves the tenant and builds its credential graph, writing the
// appropriate problem response and returning ok=false on failure.
func (a *API) buildGraph(w http.ResponseWriter, r *http.Request) (*graph.Graph, bool) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return nil, false
	}
	g, err := graph.Build(r.Context(), a.store, tenantID)
	if err != nil {
		a.writeError(w, err)
		return nil, false
	}
	return g, true
}

// trustStoresResponse answers "who trusts this CA" (epic H1).
//
// Counts are served alongside the lists because the headline an operator needs
// is a sentence — "trusted by N stores across M hosts" — and making the console
// derive it from array lengths invites two surfaces disagreeing about the same
// number.
type trustStoresResponse struct {
	Issuer string `json:"issuer"`
	// Stores are the discovered trust stores holding this CA's anchor.
	Stores []graph.Node `json:"stores"`
	// Hosts are the DISTINCT machines those stores sit on. A host running both
	// an OS store and a JVM cacerts contributes two stores and one machine to
	// visit, and the difference is the whole point of reporting both.
	Hosts      []graph.Node `json:"hosts"`
	StoreCount int          `json:"store_count"`
	HostCount  int          `json:"host_count"`
	// Guidance travels with the data rather than living in documentation nobody
	// opens during a rollover.
	Guidance string `json:"guidance"`
}

const trustStoreGuidance = "Every row here is a trust store some agent actually read on some host, " +
	"promoted from a flat finding into a relationship. Anchors are matched to a managed issuer by " +
	"SUBJECT NAME, which is the only correspondence a discovered anchor and a managed CA share — a " +
	"name match is not proof the two are the same key, so confirm the anchor's fingerprint before " +
	"acting on a rollover. Stores nobody has scanned do not appear at all, which is the honest " +
	"answer rather than a reassuring one: this is what has been observed, not what exists."

// graphTrustStores lists the trust stores that carry a given issuer's anchor.
func (a *API) graphTrustStores(w http.ResponseWriter, r *http.Request) {
	g, tenantOK := a.buildGraph(w, r)
	if !tenantOK {
		return
	}
	id := r.PathValue("id")
	node, ok := g.Node(id)
	if !ok {
		a.writeError(w, errStatus(http.StatusNotFound, "graph node not found"))
		return
	}
	if node.Kind != graph.KindIssuer {
		// Refused rather than answered with an empty list. "No stores trust this"
		// and "you asked about something that is not a CA" are different
		// statements, and an empty list for the second reads as the first.
		a.writeError(w, errStatus(http.StatusBadRequest,
			"trust stores are listed for an issuer node; "+id+" is a "+string(node.Kind)))
		return
	}
	stores, hosts := g.TrustStoresForIssuer(id)
	a.writeJSON(w, http.StatusOK, trustStoresResponse{
		Issuer: id,
		Stores: nonNilNodes(stores), Hosts: nonNilNodes(hosts),
		StoreCount: len(stores), HostCount: len(hosts),
		Guidance: trustStoreGuidance,
	})
}

// nonNilNodes keeps JSON arrays as [] rather than null, so a console can render
// an empty result without a special case.
func nonNilNodes(ns []graph.Node) []graph.Node {
	if ns == nil {
		return []graph.Node{}
	}
	return ns
}

// cryptoReadinessResponse is the sequenced crypto migration order (M2).
//
// It reports CBOM findings — including each usage”'s quantum-vulnerability flag —
// ordered by observed dependency. That is deliberately all it is: CBOM campaign
// records and findings are core, while the licensed algorithm material the
// PACKAGING-007 boundary reserves for ee/ is not implemented, named, or reachable
// from here. Sequencing what the CBOM already found is bookkeeping over the trust
// graph, not a licensed migration surface.
type cryptoReadinessResponse struct {
	Items []graph.CryptoReadinessRow `json:"items"`
	// Urgent is how many rows are quantum-vulnerable or out of policy.
	Urgent int `json:"urgent"`
	// Unlocated is how many crypto usages the CBOM recorded with no location, so
	// they have no place on the graph and no computable blast radius. Served as
	// its own count because an unplaceable asset is unmeasured, not low-risk,
	// and a total that quietly absorbed them would read as full coverage.
	Unlocated int    `json:"unlocated"`
	Guidance  string `json:"guidance"`
}

const cryptoReadinessGuidance = "Sequenced by exposure, not severity alone: two identically weak " +
	"algorithms are ordered by how many parties actually depend on them, because severity says " +
	"which crypto is worst while only dependency says which change is hard. Dependents are what " +
	"DISCOVERY HAS OBSERVED — the graph is built from scans, so an asset with zero dependents reads " +
	"identically to one on a resource nothing has scanned. No row is ever labelled safe to rotate; " +
	"confirm coverage of an asset's exhibitors before treating a low count as a low-coordination " +
	"change."

// graphCryptoReadiness sequences crypto assets by dependency and exposure (M2).
func (a *API) graphCryptoReadiness(w http.ResponseWriter, r *http.Request) {
	g, tenantOK := a.buildGraph(w, r)
	if !tenantOK {
		return
	}
	rows := g.CryptoReadiness()
	out := cryptoReadinessResponse{Items: rows, Guidance: cryptoReadinessGuidance}
	if out.Items == nil {
		out.Items = []graph.CryptoReadinessRow{}
	}
	for _, row := range rows {
		if row.QuantumVulnerable || row.OutOfPolicy {
			out.Urgent++
		}
		if row.Unlocated {
			out.Unlocated++
		}
	}
	a.writeJSON(w, http.StatusOK, out)
}
