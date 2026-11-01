// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/graph"
)

// Access questions over the credential graph (G1): who can reach a database,
// host or API, holding which credential and approved by whom, and the path one
// node takes to another. Both answers come from the same freshly built graph
// as blast radius.

type graphPathResponse struct {
	From string             `json:"from"`
	To   string             `json:"to"`
	Path graph.EvidencePath `json:"path"`
}

func (a *API) graphAccessRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/graph/path", opID: "graphPath",
			summary: "The shortest evidence path from one graph node to another",
			handler: a.graphPath, query: []param{
				{name: "from", typ: "string", desc: "Starting graph node id, for example person:<subject>", required: true},
				{name: "to", typ: "string", desc: "Target graph node id, for example res:pam:postgres:<target>", required: true},
			}, resSchema: "GraphPath", successCode: "200", perm: authz.GraphRead},
		{method: "GET", path: "/api/v1/graph/reachers/{id}", opID: "graphReachers",
			summary: "Who can reach a node: holders, credentials and approvers, each with its evidence",
			handler: a.graphReachers, pathParams: []param{pathString("id", "credential graph node id")},
			resSchema: "GraphReachers", successCode: "200", perm: authz.GraphRead},
	}
}

func (a *API) graphPath(w http.ResponseWriter, r *http.Request) {
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if from == "" || to == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "from and to are required"))
		return
	}
	g, tenantOK := a.buildGraph(w, r)
	if !tenantOK {
		return
	}
	for _, id := range []string{from, to} {
		if _, ok := g.Node(id); !ok {
			a.writeError(w, errStatus(http.StatusNotFound, "graph node not found: "+id))
			return
		}
	}
	path, ok := g.PathBetween(from, to)
	if !ok {
		a.writeError(w, errStatus(http.StatusNotFound, "no path from "+from+" to "+to+
			" in trstctl's records; that is not proof that no access exists outside them"))
		return
	}
	a.writeJSON(w, http.StatusOK, graphPathResponse{From: from, To: to, Path: path})
}

func (a *API) graphReachers(w http.ResponseWriter, r *http.Request) {
	g, tenantOK := a.buildGraph(w, r)
	if !tenantOK {
		return
	}
	id := r.PathValue("id")
	if _, ok := g.Node(id); !ok {
		a.writeError(w, errStatus(http.StatusNotFound, "graph node not found"))
		return
	}
	a.writeJSON(w, http.StatusOK, g.WhoCanReach(id))
}
