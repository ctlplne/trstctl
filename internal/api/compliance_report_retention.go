// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
)

// A206: a person holds a completed report run's signed report so the report
// retention leaves it, and releases the hold back to the retention.

type complianceReportLegalHoldRequest struct {
	Reason string `json:"reason"`
}

func mapComplianceReportHoldError(err error) error {
	var invalid *orchestrator.InvalidComplianceReportHoldError
	switch {
	case errors.As(err, &invalid):
		return errStatus(http.StatusBadRequest, strings.TrimPrefix(invalid.Error(), "orchestrator: "))
	case errors.Is(err, orchestrator.ErrComplianceReportHoldState):
		return errStatus(http.StatusConflict, "only a completed report that is not held and has not expired can be held, and only a held one released")
	case errors.Is(err, orchestrator.ErrComplianceReportBusy):
		return errStatus(http.StatusConflict, "the report run is being changed; retry")
	case errors.Is(err, pgx.ErrNoRows):
		return errStatus(http.StatusNotFound, "compliance report run not found")
	}
	return err
}

//trstctl:mutation
func (a *API) placeComplianceReportLegalHold(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "report legal holds are not configured")
		}
		id, err := reportPathUUID(r)
		if err != nil {
			return 0, nil, err
		}
		var req complianceReportLegalHoldRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, err
		}
		current, err := a.store.GetComplianceReportRun(ctx, tenantID, id)
		if err != nil {
			return 0, nil, mapComplianceReportHoldError(err)
		}
		run, err := a.orch.PlaceComplianceReportLegalHold(ctx, tenantID, id, req.Reason, a.reportStorageHoldObject(current))
		if err != nil {
			return 0, nil, mapComplianceReportHoldError(err)
		}
		responses, err := a.complianceReportRunResponses(ctx, tenantID, run)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, responses[0], nil
	})
}

//trstctl:mutation
func (a *API) releaseComplianceReportLegalHold(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "report legal holds are not configured")
		}
		id, err := reportPathUUID(r)
		if err != nil {
			return 0, nil, err
		}
		run, err := a.orch.ReleaseComplianceReportLegalHold(ctx, tenantID, id)
		if err != nil {
			return 0, nil, mapComplianceReportHoldError(err)
		}
		responses, err := a.complianceReportRunResponses(ctx, tenantID, run)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, responses[0], nil
	})
}
