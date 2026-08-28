// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/cryptoreadiness"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/orchestrator"
)

// graphResponse is the full credential graph for a tenant.
type graphResponse struct {
	Nodes []graph.Node `json:"nodes"`
	Edges []graph.Edge `json:"edges"`
}

// reachableResponse lists the nodes reachable from a starting node.
type reachableResponse struct {
	From  string               `json:"from"`
	Nodes []graph.Node         `json:"nodes"`
	Paths []graph.EvidencePath `json:"paths"`
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
	paths := g.EvidencePaths(id)
	nodes := make([]graph.Node, 0, len(paths))
	for _, path := range paths {
		nodes = append(nodes, path.Target)
	}
	a.writeJSON(w, http.StatusOK, reachableResponse{From: id, Nodes: nodes, Paths: paths})
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
	// Candidate stores share only a subject string. They are deliberately
	// separate from authoritative stores and excluded from automation.
	CandidateStores     []graph.Node `json:"candidate_stores"`
	CandidateHosts      []graph.Node `json:"candidate_hosts"`
	CandidateStoreCount int          `json:"candidate_store_count"`
	CandidateHostCount  int          `json:"candidate_host_count"`
	// Guidance travels with the data rather than living in documentation nobody
	// opens during a rollover.
	Guidance string `json:"guidance"`
}

const trustStoreGuidance = "Every row here is a trust store some agent actually read on some host, " +
	"promoted from a flat finding into a relationship. Authoritative trust requires an exact certificate " +
	"fingerprint or SPKI SHA-256 match. A shared subject name is shown only as an unverified candidate " +
	"and is excluded from counts and automation. Stores nobody has scanned do not appear at all: this " +
	"is what has been observed, not what exists."

func trustStoreGuidanceForCounts(candidateStores, candidateHosts int) string {
	return fmt.Sprintf("%d unverified subject-only candidate stores across %d hosts are excluded from authoritative counts and automation. ", candidateStores, candidateHosts) + trustStoreGuidance
}

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
	candidateStores, candidateHosts := g.TrustCandidatesForIssuer(id)
	a.writeJSON(w, http.StatusOK, trustStoresResponse{
		Issuer: id,
		Stores: nonNilNodes(stores), Hosts: nonNilNodes(hosts),
		StoreCount: len(stores), HostCount: len(hosts),
		CandidateStores: nonNilNodes(candidateStores), CandidateHosts: nonNilNodes(candidateHosts),
		CandidateStoreCount: len(candidateStores), CandidateHostCount: len(candidateHosts),
		Guidance: trustStoreGuidanceForCounts(len(candidateStores), len(candidateHosts)),
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

// graphCryptoReadiness serves the one dataset used by API, CBOM/Posture, Risk,
// workflow, and offline evidence. It is built from tenant-scoped graph authority
// plus event-projected actions; no handler owns a parallel interpretation.
func (a *API) graphCryptoReadiness(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	dataset, err := cryptoreadiness.Build(r.Context(), a.store, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, dataset)
}

// startCryptoReadinessAction creates a real event-sourced campaign action bound
// to the exact graph row and attributed owner the operator is looking at.
//
//trstctl:mutation
func (a *API) startCryptoReadinessAction(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "crypto readiness actions are not configured")
		}
		var req orchestrator.PQCMigrationCampaignStartRequest
		if err := decodePQCCampaignRequest(r, &req); err != nil {
			return 0, nil, err
		}
		campaign, err := a.orch.StartCryptoReadinessAction(ctx, tenantID, req)
		if err != nil {
			return 0, nil, mapPQCCampaignError(err)
		}
		return http.StatusCreated, toPQCCampaignResponse(campaign, true), nil
	})
}

type cryptoReadinessExportPayload struct {
	Format     string                  `json:"format"`
	Dataset    cryptoreadiness.Dataset `json:"dataset"`
	CSVHash    string                  `json:"csv_sha256"`
	NDJSONHash string                  `json:"ndjson_sha256"`
}

type cryptoReadinessExportResponse struct {
	Dataset       cryptoreadiness.Dataset `json:"dataset"`
	DatasetDigest string                  `json:"dataset_digest"`
	CSV           string                  `json:"csv"`
	NDJSON        string                  `json:"ndjson"`
	SignedExport  string                  `json:"signed_export"`
	PublicJWKS    json.RawMessage         `json:"public_jwks"`
}

// exportCryptoReadiness signs hashes of the bounded CSV and NDJSON plus the
// complete canonical dataset. An offline verifier can prove every format came
// from the same tenant-bound rows without trusting this HTTP server.
func (a *API) exportCryptoReadiness(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.pqcCampaignSigner == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "crypto readiness evidence signing is not configured"))
		return
	}
	dataset, err := cryptoreadiness.Build(r.Context(), a.store, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	csvBytes, err := cryptoreadiness.CSV(dataset)
	if err != nil {
		a.writeError(w, err)
		return
	}
	ndjsonBytes, err := cryptoreadiness.NDJSON(dataset)
	if err != nil {
		a.writeError(w, err)
		return
	}
	payload, err := json.Marshal(cryptoReadinessExportPayload{
		Format: jose.ArtifactCryptoReadiness, Dataset: dataset,
		CSVHash: "sha256:" + crypto.SHA256Hex(csvBytes), NDJSONHash: "sha256:" + crypto.SHA256Hex(ndjsonBytes),
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	signed, err := a.pqcCampaignSigner.SignArtifact(jose.ArtifactCryptoReadiness, payload)
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "sign crypto readiness evidence: "+err.Error()))
		return
	}
	jwks, err := a.pqcCampaignSigner.PublicJWKS()
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "publish crypto readiness verifier: "+err.Error()))
		return
	}
	a.writeJSON(w, http.StatusOK, cryptoReadinessExportResponse{
		Dataset: dataset, DatasetDigest: dataset.DatasetDigest, CSV: string(csvBytes),
		NDJSON: string(ndjsonBytes), SignedExport: signed, PublicJWKS: json.RawMessage(jwks),
	})
}
