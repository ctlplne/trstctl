package api

import (
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/store"
)

type crlDistributionListResponse struct {
	Items []crlDistributionResponse `json:"items"`
}

type crlDistributionResponse struct {
	TenantID        string                         `json:"tenant_id"`
	CAID            string                         `json:"ca_id"`
	FullURL         string                         `json:"full_url"`
	FullNumber      int64                          `json:"full_number"`
	ShardCount      int                            `json:"shard_count"`
	Shards          []crlDistributionShardResponse `json:"shards"`
	DeltaURL        string                         `json:"delta_url,omitempty"`
	DeltaBaseNumber int64                          `json:"delta_base_number,omitempty"`
	ThisUpdate      time.Time                      `json:"this_update"`
	NextUpdate      time.Time                      `json:"next_update"`
	RevokedCount    int                            `json:"revoked_count"`
}

type crlDistributionShardResponse struct {
	Index        int    `json:"index"`
	URL          string `json:"url"`
	RevokedCount int    `json:"revoked_count"`
}

func (a *API) listCRLDistributions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	artifacts, err := a.store.ListLatestCRLArtifactsForTenant(r.Context(), tenantID)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "CRL distribution artifacts are unavailable"))
		return
	}
	a.writeJSON(w, http.StatusOK, crlDistributionListResponse{Items: crlDistributionsFromArtifacts(tenantID, artifacts)})
}

func crlDistributionsFromArtifacts(tenantID string, artifacts []store.CRL) []crlDistributionResponse {
	var out []crlDistributionResponse
	byCA := map[string]*crlDistributionResponse{}
	for _, artifact := range artifacts {
		item := byCA[artifact.CAID]
		if item == nil {
			out = append(out, crlDistributionResponse{TenantID: tenantID, CAID: artifact.CAID})
			item = &out[len(out)-1]
			byCA[artifact.CAID] = item
		}
		switch artifact.Kind {
		case store.CRLKindFull:
			item.FullURL = "/crl/" + tenantID
			item.FullNumber = artifact.Number
			item.ShardCount = artifact.ShardCount
			item.ThisUpdate = artifact.ThisUpdate
			item.NextUpdate = artifact.NextUpdate
			item.RevokedCount = artifact.RevokedCount
		case store.CRLKindShard:
			item.Shards = append(item.Shards, crlDistributionShardResponse{
				Index: artifact.ShardIndex, URL: "/crl/" + tenantID + "/shards/" + strconv.Itoa(artifact.ShardIndex),
				RevokedCount: artifact.RevokedCount,
			})
		case store.CRLKindDelta:
			if artifact.DeltaBaseNumber != nil {
				item.DeltaBaseNumber = *artifact.DeltaBaseNumber
				item.DeltaURL = "/crl/" + tenantID + "/delta/" + strconv.FormatInt(*artifact.DeltaBaseNumber, 10)
			}
		}
	}
	return out
}
