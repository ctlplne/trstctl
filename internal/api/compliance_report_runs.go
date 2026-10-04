// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

type complianceReportRunResponse struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	ScheduleID      string     `json:"schedule_id"`
	DueAt           time.Time  `json:"due_at"`
	Framework       string     `json:"framework"`
	ReportType      string     `json:"report_type"`
	Status          string     `json:"status"`
	RetryGeneration int        `json:"retry_generation"`
	Attempt         int        `json:"attempt"`
	NextAttemptAt   *time.Time `json:"next_attempt_at,omitempty"`
	ErrorCode       string     `json:"error_code,omitempty"`
	ArtifactRef     string     `json:"artifact_ref,omitempty"`
	ArtifactDigest  string     `json:"artifact_digest,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	EventSequence   uint64     `json:"event_sequence"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func toComplianceReportRunResponse(run store.ComplianceReportRun) complianceReportRunResponse {
	out := complianceReportRunResponse{
		ID: run.ID, TenantID: run.TenantID, ScheduleID: run.ScheduleID,
		DueAt: run.DueAt, Framework: run.Framework, ReportType: run.ReportType,
		Status: run.Status, RetryGeneration: run.RetryGeneration, Attempt: run.Attempt,
		ErrorCode: run.ErrorCode, ArtifactRef: run.ArtifactRef, ArtifactDigest: run.ArtifactDigest,
		EventSequence: run.EventSequence, CreatedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt,
	}
	if !run.NextAttemptAt.IsZero() {
		next := run.NextAttemptAt
		out.NextAttemptAt = &next
	}
	if !run.CompletedAt.IsZero() {
		completed := run.CompletedAt
		out.CompletedAt = &completed
	}
	return out
}

func reportPathUUID(r *http.Request) (string, error) {
	id := strings.TrimSpace(r.PathValue("id"))
	parsed, err := googleuuid.Parse(id)
	if err != nil || parsed == googleuuid.Nil || parsed.String() != id {
		return "", errStatus(http.StatusBadRequest, "report id must be a canonical non-zero UUID")
	}
	return id, nil
}

func (a *API) listComplianceReportRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	scheduleID, err := reportPathUUID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if _, err := a.store.GetComplianceReportSchedule(r.Context(), tenantID, scheduleID); err != nil {
		a.writeError(w, complianceReportNotFound(err, "compliance report schedule not found"))
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	var before time.Time
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err == nil {
			before, err = time.Parse(time.RFC3339Nano, string(decoded))
		}
		if err != nil || before.IsZero() {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid report-run cursor"))
			return
		}
	}
	runs, err := a.store.ListComplianceReportRunsPage(r.Context(), tenantID, scheduleID, before, limit+1)
	if err != nil {
		a.writeError(w, err)
		return
	}
	hasMore := len(runs) > limit
	if hasMore {
		runs = runs[:limit]
	}
	items := make([]complianceReportRunResponse, 0, len(runs))
	for _, run := range runs {
		items = append(items, toComplianceReportRunResponse(run))
	}
	next := ""
	if hasMore {
		next = base64.RawURLEncoding.EncodeToString([]byte(runs[len(runs)-1].DueAt.UTC().Format(time.RFC3339Nano)))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getComplianceReportRun(w http.ResponseWriter, r *http.Request) {
	run, err := a.reportRunFromRequest(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toComplianceReportRunResponse(run))
}

func (a *API) downloadComplianceReportArtifact(w http.ResponseWriter, r *http.Request) {
	run, err := a.reportRunFromRequest(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if run.Status != "completed" {
		a.writeError(w, errStatus(http.StatusConflict, "report run has no completed signed artifact"))
		return
	}
	artifact, err := a.complianceReportArchive.Read(run.TenantID, run.ID, run.ArtifactDigest)
	if err != nil || a.VerifyScheduledComplianceArtifact(artifact, run) != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "signed report archive is unavailable or failed verification"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=trstctl-report-"+run.ID+".json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("ETag", `"`+run.ArtifactDigest+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(artifact)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact)
}

//trstctl:mutation
func (a *API) requeueComplianceReportRun(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		id, err := reportPathUUID(r)
		if err != nil {
			return 0, nil, err
		}
		run, err := a.store.GetComplianceReportRun(ctx, tenantID, id)
		if err != nil {
			return 0, nil, complianceReportNotFound(err, "compliance report run not found")
		}
		if run.Status != "failed" {
			return 0, nil, errStatus(http.StatusConflict, "only a failed report run can be requeued")
		}
		schedule, err := a.store.GetComplianceReportSchedule(ctx, tenantID, run.ScheduleID)
		if err != nil {
			return 0, nil, complianceReportNotFound(err, "compliance report schedule not found")
		}
		if !schedule.Enabled || !schedule.NextRunAt.Equal(run.DueAt) {
			return 0, nil, errStatus(http.StatusConflict, "report due edge is no longer active; create or resume the intended schedule")
		}
		if blockers := a.complianceReportBlockers(); len(blockers) != 0 {
			return 0, nil, errStatus(http.StatusServiceUnavailable, strings.Join(blockers, " "))
		}
		retry := run
		retry.Status = "retrying"
		retry.RetryGeneration++
		retry.Attempt = 0
		retry.NextAttemptAt = time.Now().UTC()
		retry.ErrorCode = ""
		updated, err := a.orch.RecordComplianceReportRun(ctx, retry)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toComplianceReportRunResponse(updated), nil
	})
}

func (a *API) reportRunFromRequest(r *http.Request) (store.ComplianceReportRun, error) {
	tenantID, ok := a.tenant(r)
	if !ok {
		return store.ComplianceReportRun{}, errStatus(http.StatusUnauthorized, "unauthorized")
	}
	id, err := reportPathUUID(r)
	if err != nil {
		return store.ComplianceReportRun{}, err
	}
	run, err := a.store.GetComplianceReportRun(r.Context(), tenantID, id)
	if err != nil {
		return store.ComplianceReportRun{}, complianceReportNotFound(err, "compliance report run not found")
	}
	return run, nil
}

func complianceReportNotFound(err error, message string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return errStatus(http.StatusNotFound, message)
	}
	return err
}
