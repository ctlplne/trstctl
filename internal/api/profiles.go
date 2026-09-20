// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// Certificate-profile API (S8.1): versioned CRUD over the issuance profiles. Writes
// require profiles:write (the RA role); reads require profiles:read. A create emits
// a profile.created/updated audit event via the orchestrator.

type profileRequest struct {
	Name string          `json:"name"`
	Spec json.RawMessage `json:"spec"`
}

type profileResponse struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Version   int             `json:"version"`
	Active    bool            `json:"active"`
	CreatedBy string          `json:"created_by"`
	Spec      json.RawMessage `json:"spec"`
}

type profileApprovalResponse struct {
	ApprovalID string `json:"approval_id"`
	State      string `json:"state"`
	Resource   string `json:"resource"`
}

type profileRestoreRequest struct {
	ExpectedActiveVersion int    `json:"expected_active_version"`
	Reason                string `json:"reason"`
}

func toProfileResponse(r store.ProfileRecord) profileResponse {
	return profileResponse{ID: r.ID, Name: r.Name, Version: r.Version, Active: r.Active, CreatedBy: r.CreatedBy, Spec: r.Spec}
}

//trstctl:mutation
func (a *API) createProfile(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req profileRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.Name == "" || len(req.Spec) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "name and spec are required")
		}
		if err := profile.ValidateSpec(req.Spec); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		rec, err := a.orch.CreateProfile(ctx, tenantID, req.Name, req.Spec)
		if err != nil {
			var pending *orchestrator.ProfileEditPendingError
			if errors.As(err, &pending) {
				return http.StatusAccepted, profileApprovalResponse{
					ApprovalID: pending.Request.ID,
					State:      string(pending.Request.State),
					Resource:   pending.Request.Resource,
				}, nil
			}
			return 0, nil, err
		}
		return http.StatusCreated, toProfileResponse(rec), nil
	})
}

func (a *API) listProfiles(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	recs, err := a.store.ListProfiles(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]profileResponse, 0, len(recs))
	for _, rec := range recs {
		items = append(items, toProfileResponse(rec))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) getProfileVersion(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version < 1 {
		a.writeError(w, errStatus(http.StatusBadRequest, "version must be a positive integer"))
		return
	}
	rec, err := a.store.GetProfileVersion(r.Context(), tenantID, r.PathValue("name"), version)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toProfileResponse(rec))
}

func decodeProfileRestoreRequest(r *http.Request) (profileRestoreRequest, error) {
	var req profileRestoreRequest
	if err := decodeJSON(r, &req); err != nil {
		return profileRestoreRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	if req.ExpectedActiveVersion < 1 {
		return profileRestoreRequest{}, errStatus(http.StatusBadRequest, "expected_active_version must be a positive integer")
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if len(req.Reason) == 0 {
		return profileRestoreRequest{}, errStatus(http.StatusBadRequest, "reason is required")
	}
	if len(req.Reason) > 1000 {
		return profileRestoreRequest{}, errStatus(http.StatusBadRequest, "reason must be 1000 characters or fewer")
	}
	return req, nil
}

func profileVersionFromPath(r *http.Request) (int, error) {
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version < 1 {
		return 0, errStatus(http.StatusBadRequest, "version must be a positive integer")
	}
	return version, nil
}

func profileRestoreAPIError(err error) error {
	switch {
	case errors.Is(err, orchestrator.ErrProfileRestoreStale):
		return errStatus(http.StatusConflict, "The active rule changed after this recovery was reviewed. Preview it again before restoring.")
	case errors.Is(err, orchestrator.ErrProfileRestoreAlreadyActive):
		return errStatus(http.StatusConflict, "The selected rule version is already active; no recovery change is needed.")
	default:
		return err
	}
}

// previewProfileRestore is intentionally a POST-shaped read because the exact
// proposal is in the request body. It emits no event and contacts no external
// system; the mutation rechecks the active-version fence at confirmation time.
func (a *API) previewProfileRestore(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	version, err := profileVersionFromPath(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	req, err := decodeProfileRestoreRequest(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	plan, err := a.orch.PlanProfileRestore(r.Context(), tenantID, r.PathValue("name"), version, req.ExpectedActiveVersion, req.Reason)
	if err != nil {
		a.writeError(w, profileRestoreAPIError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

//trstctl:mutation
func (a *API) restoreProfileVersion(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		version, err := profileVersionFromPath(r)
		if err != nil {
			return 0, nil, err
		}
		req, err := decodeProfileRestoreRequest(r)
		if err != nil {
			return 0, nil, err
		}
		rec, err := a.orch.RestoreProfileVersion(ctx, tenantID, r.PathValue("name"), version, req.ExpectedActiveVersion, req.Reason)
		if err != nil {
			var pending *orchestrator.ProfileEditPendingError
			if errors.As(err, &pending) {
				return http.StatusAccepted, profileApprovalResponse{
					ApprovalID: pending.Request.ID,
					State:      string(pending.Request.State),
					Resource:   pending.Request.Resource,
				}, nil
			}
			return 0, nil, profileRestoreAPIError(err)
		}
		return http.StatusCreated, toProfileResponse(rec), nil
	})
}
