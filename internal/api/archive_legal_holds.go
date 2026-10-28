// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/reportarchive"
	"trstctl.com/trstctl/internal/store"
)

// A208: a person's S3 legal hold on one archive object under the tenant's
// prefix (a report artifact, an audit archive segment). The outbox sets it in
// the bucket and it reads applied only after the bucket reads it back.

type archiveLegalHoldRequest struct {
	Object string `json:"object"`
	Reason string `json:"reason"`
}

type archiveLegalHoldResponse struct {
	ID           string     `json:"id"`
	Object       string     `json:"object"`
	Reason       string     `json:"reason"`
	ReportRunID  string     `json:"report_run_id,omitempty"`
	PlacedBy     string     `json:"placed_by"`
	PlacedAt     time.Time  `json:"placed_at"`
	Status       string     `json:"status"`
	StatusDetail string     `json:"status_detail,omitempty"`
	AppliedAt    *time.Time `json:"applied_at,omitempty"`
	ReleasedAt   *time.Time `json:"released_at,omitempty"`
}

func toArchiveLegalHoldResponse(h store.ArchiveLegalHold) archiveLegalHoldResponse {
	return archiveLegalHoldResponse{ID: h.ID, Object: h.Object, Reason: h.Reason, ReportRunID: h.ReportRunID,
		PlacedBy: h.PlacedBy, PlacedAt: h.PlacedAt, Status: h.Status, StatusDetail: h.StatusDetail,
		AppliedAt: h.AppliedAt, ReleasedAt: h.ReleasedAt}
}

// archiveStorageHoldStatus is a report legal hold's hold on its object.
type archiveStorageHoldStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func mapArchiveLegalHoldError(err error) error {
	var invalid *orchestrator.InvalidComplianceReportHoldError
	switch {
	case errors.As(err, &invalid):
		return errStatus(http.StatusBadRequest, strings.TrimPrefix(invalid.Error(), "orchestrator: "))
	case errors.Is(err, store.ErrArchiveLegalHoldState):
		return errStatus(http.StatusConflict, "the object already has an active legal hold, or this hold is not pending or applied")
	case errors.Is(err, orchestrator.ErrArchiveLegalHoldLinked):
		return errStatus(http.StatusConflict, "this storage hold belongs to a report's legal hold; release that hold instead")
	case errors.Is(err, pgx.ErrNoRows):
		return errStatus(http.StatusNotFound, "archive legal hold not found")
	}
	return err
}

// lockableArchive returns the archive object store when it can hold objects.
func (a *API) lockableArchive() (objectstore.Locker, bool) {
	locker, ok := a.complianceReportArchive.Objects.(objectstore.Locker)
	return locker, ok && a.complianceReportArchive.Objects != nil
}

// reportStorageHoldObject names a report's object when a report legal hold
// should also hold it in the bucket: the report is in an archive object store
// the deployment writes under S3 Object Lock.
func (a *API) reportStorageHoldObject(run store.ComplianceReportRun) string {
	if run.ArtifactRef == "" || reportarchive.IsDirectoryReference(run.ArtifactRef) {
		return ""
	}
	if _, ok := a.lockableArchive(); !ok {
		return ""
	}
	configured, ok := a.complianceReportArchive.Objects.(interface{ LockConfigured() bool })
	if !ok || !configured.LockConfigured() {
		return ""
	}
	return run.ArtifactRef
}

// complianceReportRunResponses adds each held run's storage hold.
func (a *API) complianceReportRunResponses(ctx context.Context, tenantID string, runs ...store.ComplianceReportRun) ([]complianceReportRunResponse, error) {
	ids := make([]string, 0, len(runs))
	for _, run := range runs {
		if run.Retention.Held() {
			ids = append(ids, run.ID)
		}
	}
	holds, err := a.store.ArchiveLegalHoldsForReportRuns(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	out := make([]complianceReportRunResponse, 0, len(runs))
	for _, run := range runs {
		resp := toComplianceReportRunResponse(run)
		if h, ok := holds[run.ID]; ok && resp.LegalHold != nil {
			resp.LegalHold.Storage = &archiveStorageHoldStatus{ID: h.ID, Status: h.Status, Detail: h.StatusDetail}
		}
		out = append(out, resp)
	}
	return out, nil
}

//trstctl:mutation
func (a *API) placeArchiveLegalHold(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "archive legal holds are not configured")
		}
		locker, ok := a.lockableArchive()
		if !ok {
			return 0, nil, errStatus(http.StatusConflict, "no archive object store with S3 Object Lock is configured; archive legal holds need one")
		}
		var req archiveLegalHoldRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		object := strings.TrimSpace(req.Object)
		view, err := objectstore.ForTenant(ctx, a.complianceReportArchive.Objects, tenantID)
		if err != nil {
			return 0, nil, err
		}
		if objectstore.ValidName(object, false) != nil || !strings.HasPrefix(object, view.Prefix()) {
			return 0, nil, errStatus(http.StatusBadRequest, "object must name an archive object under this tenant's prefix "+view.Prefix())
		}
		if _, err := locker.Lock(ctx, object); errors.Is(err, objectstore.ErrNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "no archive object "+object)
		} else if err != nil {
			return 0, nil, err
		}
		hold, err := a.orch.PlaceArchiveLegalHold(ctx, tenantID, object, req.Reason)
		if err != nil {
			return 0, nil, mapArchiveLegalHoldError(err)
		}
		return http.StatusCreated, toArchiveLegalHoldResponse(hold), nil
	})
}

//trstctl:mutation
func (a *API) releaseArchiveLegalHold(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "archive legal holds are not configured")
		}
		id, err := reportPathUUID(r)
		if err != nil {
			return 0, nil, err
		}
		hold, err := a.orch.ReleaseArchiveLegalHold(ctx, tenantID, id)
		if err != nil {
			return 0, nil, mapArchiveLegalHoldError(err)
		}
		return http.StatusOK, toArchiveLegalHoldResponse(hold), nil
	})
}

func (a *API) listArchiveLegalHolds(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	holds, err := a.store.ListArchiveLegalHolds(r.Context(), tenantID, 500)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]archiveLegalHoldResponse, 0, len(holds))
	for _, h := range holds {
		items = append(items, toArchiveLegalHoldResponse(h))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}
