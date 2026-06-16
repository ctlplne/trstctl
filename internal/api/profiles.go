package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

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

func toProfileResponse(r store.ProfileRecord) profileResponse {
	return profileResponse{ID: r.ID, Name: r.Name, Version: r.Version, Active: r.Active, CreatedBy: r.CreatedBy, Spec: r.Spec}
}

func (a *API) createProfile(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req profileRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		if req.Name == "" || len(req.Spec) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "name and spec are required")
		}
		rec, err := a.orch.CreateProfile(ctx, tenantID, req.Name, req.Spec)
		if err != nil {
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
