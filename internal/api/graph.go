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
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
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
