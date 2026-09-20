// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca/adcs"
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

const adcsDatabaseGuidance = "The domain-joined relay collects certutil rows from a CA database; " +
	"the control plane parses and summarizes them by disposition. Pending is a request awaiting a CA " +
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
	Items    []adcsDatabaseSummaryResponse `json:"items"`
	Guidance string                        `json:"guidance"`
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
	out := adcsDatabaseList{Items: []adcsDatabaseSummaryResponse{}, Guidance: adcsDatabaseGuidance}
	for _, s := range summaries {
		out.Items = append(out.Items, adcsDatabaseSummaryFrom(s))
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
