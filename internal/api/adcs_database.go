// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/ca/adcs"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// AD CS certificate-database ingestion and lifecycle visibility (epic F4).
//
// Issuing against an enterprise CA gives no visibility into what that CA holds.
// A domain-joined relay collects certutil rows; this surface ingests them —
// parsing and summarizing by disposition — and serves the per-CA breakdown an
// operator needs: what is issued, what is PENDING a CA manager's approval, and
// what was revoked, denied, or failed. Pending is kept distinct from failed on
// purpose: a pending request shown as failed makes an operator resubmit instead
// of getting it approved.

const adcsDatabaseGuidance = "A domain-joined Windows relay reads a CA database with certutil and returns only " +
	"per-disposition counts (POST /api/v1/adcs/ca-database/collect), or certutil rows are ingested and " +
	"summarized here. Pending is a request awaiting a CA " +
	"manager's approval — distinct from failed and denied, because the fix for a pending request is " +
	"approval, not resubmission. Rows that carry no request id are counted as rejected, never dropped, " +
	"so a collection problem cannot pass for an empty CA. This is VISIBILITY, not control: trstctl reads " +
	"the CA database, it does not approve or revoke through this surface."

type adcsDatabaseIngestBody struct {
	CAConfig string `json:"ca_config"`
	// Rows are certutil-shaped field maps, exactly as the relay collected them.
	Rows      []map[string]string `json:"rows"`
	Source    string              `json:"source,omitempty"`
	LastError string              `json:"last_error,omitempty"`
}

type adcsDatabaseSummaryResponse struct {
	CAConfig     string `json:"ca_config"`
	Issued       int    `json:"issued"`
	Pending      int    `json:"pending"`
	Revoked      int    `json:"revoked"`
	Denied       int    `json:"denied"`
	Failed       int    `json:"failed"`
	Unknown      int    `json:"unknown"`
	Unparsed     int    `json:"unparsed"`
	Total        int    `json:"total"`
	RowsRead     int    `json:"rows_read"`
	RowsRejected int    `json:"rows_rejected"`
	Source       string `json:"source,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	IngestedAt   string `json:"ingested_at,omitempty"`
}

type adcsDatabaseList struct {
	Items []adcsDatabaseSummaryResponse `json:"items"`
	// Collections are the newest relay reads and the status each reached
	// (A162), so a failed read is visible even for a CA never read before.
	Collections []adcsDatabaseCollectionResponse `json:"collections"`
	Guidance    string                           `json:"guidance"`
}

type adcsDatabaseCollectBody struct {
	CAConfig     string `json:"ca_config"`
	RelayAgentID string `json:"relay_agent_id"`
}

type adcsDatabaseCollectionResponse struct {
	CollectionID string `json:"collection_id"`
	CAConfig     string `json:"ca_config"`
	RelayAgentID string `json:"relay_agent_id"`
	Status       string `json:"status"`
	Attempts     int    `json:"attempts"`
	LastError    string `json:"last_error,omitempty"`
	RequestedAt  string `json:"requested_at,omitempty"`
	CompletedAt  string `json:"completed_at,omitempty"`
}

// collectADCSDatabase asks one exact domain-joined network relay to read one
// CA's database with certutil (A162). The relay runs certutil as its own
// domain identity and returns per-disposition counts only; no subject,
// requester or certificate leaves it.
func (a *API) collectADCSDatabase(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errors.New("CA database reads are unavailable")
		}
		var body adcsDatabaseCollectBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		caConfig := strings.TrimSpace(body.CAConfig)
		if !relay.ValidCAConfig(caConfig) {
			return 0, nil, errStatus(http.StatusBadRequest, "ca_config must be certsrv's own HOST\\CA-Name identifier: printable, without quotes, and not option-shaped")
		}
		relayID := strings.TrimSpace(body.RelayAgentID)
		if parsed, err := googleuuid.Parse(relayID); err != nil || parsed.String() != relayID {
			return 0, nil, errStatus(http.StatusBadRequest, "relay_agent_id must name the domain-joined network relay that runs certutil, by its agent id")
		}
		requested, err := a.orch.RequestADCSDatabaseCollection(ctx, tenantID, orchestrator.ADCSDatabaseCollectionRequest{
			CAConfig: caConfig, RequiredAgentID: relayID, IdempotencyKey: idempotencyKey,
		})
		if errors.Is(err, orchestrator.ErrDiscoveryRelayUnavailable) {
			return 0, nil, errStatus(http.StatusConflict, discoveryRelayUnavailableDetail(err, false))
		}
		if errors.Is(err, orchestrator.ErrADCSDatabaseCollectionPending) {
			return 0, nil, errStatus(http.StatusConflict, "A read of this CA's database is already waiting or running. Wait for its result before asking again.")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, adcsDatabaseCollectionResponse{
			CollectionID: requested.CollectionID, CAConfig: requested.CAConfig,
			RelayAgentID: requested.AgentID, Status: "queued",
		}, nil
	})
}

func (a *API) ingestADCSDatabase(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body adcsDatabaseIngestBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(body.CAConfig) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "ca_config is required: it is certsrv's own HOST\\CA-Name identifier")
		}
		// Parse and summarize HERE — the production caller of adcs.ParseDBRow and
		// adcs.Summarize. A row that will not parse is COUNTED rejected, never
		// dropped, so a collection problem cannot masquerade as an empty CA.
		parsed := make([]adcs.DBRow, 0, len(body.Rows))
		rejected := 0
		for _, fields := range body.Rows {
			row, err := adcs.ParseDBRow(fields)
			if err != nil {
				rejected++
				continue
			}
			parsed = append(parsed, row)
		}
		summary := adcs.Summarize(parsed)
		ingested := projections.ADCSDatabaseIngested{
			CAConfig:     strings.TrimSpace(body.CAConfig),
			Issued:       summary.Issued,
			Pending:      summary.Pending,
			Revoked:      summary.Revoked,
			Denied:       summary.Denied,
			Failed:       summary.Failed,
			Unknown:      summary.Unknown,
			Unparsed:     summary.Unparsed,
			Total:        summary.Total,
			RowsRead:     len(body.Rows),
			RowsRejected: rejected,
			Source:       strings.TrimSpace(body.Source),
			LastError:    strings.TrimSpace(body.LastError),
		}
		if err := a.orch.RecordADCSDatabaseIngested(ctx, tenantID, ingested); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, adcsDatabaseSummaryResponse{
			CAConfig: ingested.CAConfig, Issued: ingested.Issued, Pending: ingested.Pending,
			Revoked: ingested.Revoked, Denied: ingested.Denied, Failed: ingested.Failed,
			Unknown: ingested.Unknown, Unparsed: ingested.Unparsed, Total: ingested.Total,
			RowsRead: ingested.RowsRead, RowsRejected: ingested.RowsRejected,
			Source: ingested.Source, LastError: ingested.LastError,
		}, nil
	})
}

func (a *API) listADCSDatabases(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	summaries, err := a.store.ListADCSDatabaseSummaries(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	collections, err := a.store.ListADCSDatabaseCollections(r.Context(), tenantID, 20)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := adcsDatabaseList{Items: []adcsDatabaseSummaryResponse{}, Collections: []adcsDatabaseCollectionResponse{}, Guidance: adcsDatabaseGuidance}
	for _, s := range summaries {
		out.Items = append(out.Items, adcsDatabaseSummaryFrom(s))
	}
	for _, c := range collections {
		resp := adcsDatabaseCollectionResponse{
			CollectionID: c.CollectionID, CAConfig: c.CAConfig, RelayAgentID: c.AgentID,
			Status: c.Status, Attempts: c.Attempts, LastError: c.LastError,
			RequestedAt: c.RequestedAt.UTC().Format(time.RFC3339),
		}
		if c.CompletedAt != nil {
			resp.CompletedAt = c.CompletedAt.UTC().Format(time.RFC3339)
		}
		out.Collections = append(out.Collections, resp)
	}
	a.writeJSON(w, http.StatusOK, out)
}

func adcsDatabaseSummaryFrom(s store.ADCSDatabaseSummary) adcsDatabaseSummaryResponse {
	resp := adcsDatabaseSummaryResponse{
		CAConfig: s.CAConfig, Issued: s.Issued, Pending: s.Pending, Revoked: s.Revoked,
		Denied: s.Denied, Failed: s.Failed, Unknown: s.Unknown, Unparsed: s.Unparsed,
		Total: s.Total, RowsRead: s.RowsRead, RowsRejected: s.RowsRejected,
		Source: s.Source, LastError: s.LastError,
	}
	if !s.IngestedAt.IsZero() {
		resp.IngestedAt = s.IngestedAt.UTC().Format(time.RFC3339)
	}
	return resp
}
