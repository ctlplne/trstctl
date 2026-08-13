// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"time"
)

// RevocationCacheStatus is one signed relay-local CRL or OCSP cache. Upstream
// URLs and cached protocol bytes never cross the agent boundary.
type RevocationCacheStatus struct {
	AgentID           string `json:"agent_id"`
	AgentName         string `json:"agent_name"`
	Segment           string `json:"segment"`
	CacheID           string `json:"cache_id"`
	Protocol          string `json:"protocol"`
	IssuerFingerprint string `json:"issuer_fingerprint"`
	LocalPath         string `json:"local_path"`
	Status            string `json:"status"`
	DetailCode        string `json:"detail_code,omitempty"`
	CachedResponses   int    `json:"cached_responses"`
	Fresh             bool   `json:"fresh"`
	SignatureVerified bool   `json:"signature_verified"`
	MetadataOnly      bool   `json:"metadata_only"`
	ThisUpdate        string `json:"this_update,omitempty"`
	NextUpdate        string `json:"next_update,omitempty"`
	LastValidatedAt   string `json:"last_validated_at,omitempty"`
	ServedRequests    int64  `json:"served_requests"`
	RefusedRequests   int64  `json:"refused_requests"`
	SignerFingerprint string `json:"signer_fingerprint"`
	ReportedAt        string `json:"reported_at"`
}

type RevocationCacheSummary struct {
	Caches int `json:"caches"`
	Fresh  int `json:"fresh"`
	Stale  int `json:"stale"`
	Empty  int `json:"empty"`
	Error  int `json:"error"`
}

type RevocationCachePosture struct {
	Observed bool                    `json:"observed"`
	Items    []RevocationCacheStatus `json:"items"`
	Summary  RevocationCacheSummary  `json:"summary"`
	Guidance string                  `json:"guidance"`
}

const revocationCacheGuidance = "Each row is signed by the certificate-bound network relay and names one segment, issuer, and protocol cache. Fresh means the relay verified the CA or OCSP responder signature and the signed nextUpdate has not passed. Stale, empty, or error means isolated clients cannot rely on that local route; the relay fails closed instead of serving an expired response."

func (a *API) listRevocationCaches(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "revocation cache posture is not configured"))
		return
	}
	rows, err := a.store.ListAgentRevocationCaches(r.Context(), tenantID, 1000)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := RevocationCachePosture{
		Observed: len(rows) > 0, Items: make([]RevocationCacheStatus, 0, len(rows)),
		Summary: RevocationCacheSummary{Caches: len(rows)}, Guidance: revocationCacheGuidance,
	}
	for _, row := range rows {
		entry := row.Entry
		item := RevocationCacheStatus{
			AgentID: row.AgentID, AgentName: row.AgentName, Segment: entry.Segment,
			CacheID: entry.CacheID, Protocol: entry.Protocol, IssuerFingerprint: entry.IssuerFingerprint,
			LocalPath: entry.LocalPath, Status: entry.Status, DetailCode: entry.DetailCode,
			CachedResponses: entry.CachedResponses, Fresh: entry.Fresh,
			SignatureVerified: entry.SignatureVerified, MetadataOnly: true,
			ServedRequests: entry.ServedRequests, RefusedRequests: entry.RefusedRequests,
			SignerFingerprint: row.SignerFingerprint, ReportedAt: row.ReportedAt.UTC().Format(time.RFC3339),
		}
		if entry.ThisUpdateUnix > 0 {
			item.ThisUpdate = time.Unix(entry.ThisUpdateUnix, 0).UTC().Format(time.RFC3339)
		}
		if entry.NextUpdateUnix > 0 {
			item.NextUpdate = time.Unix(entry.NextUpdateUnix, 0).UTC().Format(time.RFC3339)
		}
		if entry.LastValidatedAtUnix > 0 {
			item.LastValidatedAt = time.Unix(entry.LastValidatedAtUnix, 0).UTC().Format(time.RFC3339)
		}
		switch entry.Status {
		case "fresh":
			out.Summary.Fresh++
		case "stale":
			out.Summary.Stale++
		case "empty":
			out.Summary.Empty++
		case "error":
			out.Summary.Error++
		}
		out.Items = append(out.Items, item)
	}
	a.writeJSON(w, http.StatusOK, out)
}
