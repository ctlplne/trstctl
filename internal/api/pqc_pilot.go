// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// PQC pilot waves (A28/A29): a staged post-quantum handshake proof over
// relay-probed endpoints, halting on the canary's evidence.

type pqcPilotStartRequest struct {
	ID             string                `json:"id,omitempty"`
	Name           string                `json:"name"`
	AuthorityID    string                `json:"authority_id,omitempty"`
	TimeoutSeconds int                   `json:"timeout_seconds,omitempty"`
	Waves          []pqcPilotWaveRequest `json:"waves"`
}

type pqcPilotWaveRequest struct {
	Name    string                  `json:"name"`
	Targets []pqcPilotTargetRequest `json:"targets"`
}

type pqcPilotTargetRequest struct {
	TargetID    string `json:"target_id"`
	Address     string `json:"address"`
	ServerName  string `json:"server_name,omitempty"`
	Connector   string `json:"connector,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

type pqcPilotResponse struct {
	ID             string                 `json:"id"`
	TenantID       string                 `json:"tenant_id"`
	Name           string                 `json:"name"`
	AuthorityID    string                 `json:"authority_id,omitempty"`
	RequestedBy    string                 `json:"requested_by,omitempty"`
	Status         string                 `json:"status"`
	WaveCount      int                    `json:"wave_count"`
	CurrentWave    int                    `json:"current_wave"`
	HaltedAtWave   string                 `json:"halted_at_wave,omitempty"`
	VerdictSummary string                 `json:"verdict_summary,omitempty"`
	SignedReport   json.RawMessage        `json:"signed_report,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	FinishedAt     *time.Time             `json:"finished_at,omitempty"`
	Waves          []pqcPilotWaveResponse `json:"waves,omitempty"`
}

type pqcPilotWaveResponse struct {
	Index          int                     `json:"index"`
	Name           string                  `json:"name"`
	Status         string                  `json:"status"`
	Targets        []pqcPilotTargetRequest `json:"targets"`
	OutboxID       *int64                  `json:"outbox_id,omitempty"`
	IdempotencyKey string                  `json:"idempotency_key,omitempty"`
	Results        []pqcPilotResultRes     `json:"results,omitempty"`
	Verdict        *pqcPilotVerdictRes     `json:"verdict,omitempty"`
	DispatchedAt   *time.Time              `json:"dispatched_at,omitempty"`
	AssessedAt     *time.Time              `json:"assessed_at,omitempty"`
}

type pqcPilotResultRes struct {
	TargetID        string    `json:"target_id"`
	Outcome         string    `json:"outcome"`
	HandshakeMillis int64     `json:"handshake_ms"`
	ChainBytes      int       `json:"chain_bytes"`
	Detail          string    `json:"detail,omitempty"`
	EvidenceDigest  string    `json:"evidence_digest,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
}

type pqcPilotVerdictRes struct {
	Ready        bool   `json:"ready"`
	Halt         bool   `json:"halt"`
	Summary      string `json:"summary"`
	Negotiated   int    `json:"negotiated"`
	Rejected     int    `json:"rejected"`
	Unreachable  int    `json:"unreachable"`
	NotAttempted int    `json:"not_attempted"`
}

func toPQCPilotResponse(p store.PQCPilot, withWaves bool) pqcPilotResponse {
	out := pqcPilotResponse{
		ID: p.ID, TenantID: p.TenantID, Name: p.Name, AuthorityID: p.AuthorityID, RequestedBy: p.RequestedBy,
		Status: p.Status, WaveCount: p.WaveCount, CurrentWave: p.CurrentWave, HaltedAtWave: p.HaltedAtWave,
		VerdictSummary: p.VerdictSummary, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, FinishedAt: p.FinishedAt,
	}
	if p.SignedReport != "" && json.Valid([]byte(p.SignedReport)) {
		out.SignedReport = json.RawMessage(p.SignedReport)
	}
	if !withWaves {
		return out
	}
	for _, w := range p.Waves {
		wave := pqcPilotWaveResponse{Index: w.Index, Name: w.Name, Status: w.Status, OutboxID: w.OutboxID,
			IdempotencyKey: w.IdempotencyKey, DispatchedAt: w.DispatchedAt, AssessedAt: w.AssessedAt, Targets: []pqcPilotTargetRequest{}}
		for _, t := range w.Targets {
			wave.Targets = append(wave.Targets, pqcPilotTargetRequest{TargetID: t.TargetID, Address: t.Address,
				ServerName: t.ServerName, Connector: t.Connector, Fingerprint: t.Fingerprint})
		}
		for _, r := range w.Results {
			wave.Results = append(wave.Results, pqcPilotResultRes{TargetID: r.TargetID, Outcome: r.Outcome,
				HandshakeMillis: r.HandshakeMillis, ChainBytes: r.ChainBytes, Detail: r.Detail,
				EvidenceDigest: r.EvidenceDigest, ObservedAt: r.ObservedAt})
		}
		if w.Verdict != nil {
			v := *w.Verdict
			wave.Verdict = &pqcPilotVerdictRes{Ready: v.Ready, Halt: v.Halt, Summary: v.Summary, Negotiated: v.Negotiated,
				Rejected: v.Rejected, Unreachable: v.Unreachable, NotAttempted: v.NotAttempted}
		}
		out.Waves = append(out.Waves, wave)
	}
	return out
}

//trstctl:mutation
func (a *API) startPQCPilot(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC pilots are not configured")
		}
		var req pqcPilotStartRequest
		if err := decodePQCCampaignRequest(r, &req); err != nil {
			return 0, nil, err
		}
		in := orchestrator.PQCPilotStartRequest{ID: req.ID, Name: req.Name, AuthorityID: req.AuthorityID,
			RequestedBy: principal.Subject, TimeoutSeconds: req.TimeoutSeconds}
		for _, wave := range req.Waves {
			wr := orchestrator.PQCPilotWaveRequest{Name: wave.Name}
			for _, t := range wave.Targets {
				wr.Targets = append(wr.Targets, orchestrator.PQCPilotTargetRequest{TargetID: t.TargetID, Address: t.Address,
					ServerName: t.ServerName, Connector: t.Connector, Fingerprint: t.Fingerprint})
			}
			in.Waves = append(in.Waves, wr)
		}
		pilot, err := a.orch.StartPQCPilot(ctx, tenantID, in)
		if err != nil {
			return 0, nil, mapPQCPilotError(err)
		}
		return http.StatusCreated, toPQCPilotResponse(pilot, true), nil
	})
}

func (a *API) listPQCPilots(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListPQCPilotsPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]pqcPilotResponse, 0, len(rows))
	for _, pilot := range rows {
		items = append(items, toPQCPilotResponse(pilot, false))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getPQCPilot(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	pilot, err := a.store.GetPQCPilot(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, mapPQCPilotError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, toPQCPilotResponse(pilot, true))
}

func mapPQCPilotError(err error) error {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		return ae
	case store.IsNotFound(err):
		return errStatus(http.StatusNotFound, "PQC pilot not found")
	case errors.Is(err, store.ErrPQCPilotExists), errors.Is(err, orchestrator.ErrPQCPilotFinished):
		return errStatus(http.StatusConflict, err.Error())
	case errors.Is(err, orchestrator.ErrPQCPilotInvalid):
		return errStatus(http.StatusUnprocessableEntity, err.Error())
	default:
		return errStatus(http.StatusBadRequest, err.Error())
	}
}
