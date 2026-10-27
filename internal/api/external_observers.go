// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A180: external observers (probectl or any monitor) report what they saw at
// endpoints and receive rotation and rollback events.

type observerRequest struct {
	Name          string `json:"name"`
	EventsURL     string `json:"events_url"`
	CredentialRef string `json:"credential_ref"`
	Enabled       *bool  `json:"enabled"`
}

type observerResponse struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	EventsURL     string    `json:"events_url"`
	CredentialRef string    `json:"credential_ref"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type observationRequest struct {
	ObserverID        string    `json:"observer_id"`
	Endpoint          string    `json:"endpoint"`
	Vantage           string    `json:"vantage"`
	ObservedAt        time.Time `json:"observed_at"`
	Reachable         bool      `json:"reachable"`
	Health            string    `json:"health"`
	ServedFingerprint string    `json:"served_fingerprint"`
	ChainFingerprints []string  `json:"chain_fingerprints"`
	Detail            string    `json:"detail"`
}

type observationResponse struct {
	ID                  string    `json:"id"`
	ObserverID          string    `json:"observer_id"`
	ObserverName        string    `json:"observer_name"`
	Endpoint            string    `json:"endpoint"`
	Vantage             string    `json:"vantage"`
	ObservedAt          time.Time `json:"observed_at"`
	Reachable           bool      `json:"reachable"`
	Health              string    `json:"health"`
	ServedFingerprint   string    `json:"served_fingerprint"`
	ChainFingerprints   []string  `json:"chain_fingerprints"`
	Detail              string    `json:"detail"`
	ExpectedFingerprint string    `json:"expected_fingerprint"`
	Verdict             string    `json:"verdict"`
	RecordedAt          time.Time `json:"recorded_at"`
}

func toObserverResponse(o store.ExternalObserver) observerResponse {
	return observerResponse{
		ID: o.ID, Name: o.Name, EventsURL: o.EventsURL, CredentialRef: o.CredentialRef, Enabled: o.Enabled,
		CreatedAt: o.CreatedAt, UpdatedAt: o.UpdatedAt,
	}
}

func toObservationResponse(o store.ExternalObservation) observationResponse {
	chain := o.ChainFingerprints
	if chain == nil {
		chain = []string{}
	}
	return observationResponse{
		ID: o.ID, ObserverID: o.ObserverID, ObserverName: o.ObserverName, Endpoint: o.Endpoint, Vantage: o.Vantage,
		ObservedAt: o.ObservedAt, Reachable: o.Reachable, Health: o.Health, ServedFingerprint: o.ServedFingerprint,
		ChainFingerprints: chain, Detail: o.Detail, ExpectedFingerprint: o.ExpectedFingerprint,
		Verdict: o.Verdict, RecordedAt: o.RecordedAt,
	}
}

func observerInput(req observerRequest, enabledDefault bool) orchestrator.ObserverInput {
	enabled := enabledDefault
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return orchestrator.ObserverInput{Name: req.Name, EventsURL: req.EventsURL, CredentialRef: req.CredentialRef, Enabled: enabled}
}

func mapObserverError(err error) error {
	var invalid *orchestrator.InvalidObserverError
	switch {
	case errors.As(err, &invalid):
		return errStatus(http.StatusBadRequest, strings.TrimPrefix(invalid.Error(), "orchestrator: "))
	case errors.Is(err, orchestrator.ErrObserverNameTaken):
		return errStatus(http.StatusConflict, "an observer of that name exists")
	case errors.Is(err, orchestrator.ErrObserverUnavailable):
		return errStatus(http.StatusConflict, "the observer is not registered or not enabled in this tenant")
	}
	return err
}

//trstctl:mutation
func (a *API) registerObserver(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "observers are not configured")
		}
		var req observerRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, err
		}
		observer, err := a.orch.RegisterObserver(ctx, tenantID, observerInput(req, true))
		if err != nil {
			return 0, nil, mapObserverError(err)
		}
		return http.StatusCreated, toObserverResponse(observer), nil
	})
}

//trstctl:mutation
func (a *API) updateObserver(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "observers are not configured")
		}
		var req observerRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, err
		}
		observer, err := a.orch.UpdateObserver(ctx, tenantID, r.PathValue("id"), observerInput(req, true))
		if err != nil {
			return 0, nil, mapObserverError(err)
		}
		return http.StatusOK, toObserverResponse(observer), nil
	})
}

func (a *API) listObservers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	observers, err := a.store.ListExternalObservers(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := make([]observerResponse, 0, len(observers))
	for _, observer := range observers {
		out = append(out, toObserverResponse(observer))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

//trstctl:mutation
func (a *API) recordObservation(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "observations are not configured")
		}
		var req observationRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, err
		}
		if req.ObservedAt.IsZero() {
			return 0, nil, errStatus(http.StatusBadRequest, "observed_at is required")
		}
		observation, err := a.orch.RecordObservation(ctx, tenantID, key, orchestrator.ObservationInput{
			ObserverID: req.ObserverID, Endpoint: req.Endpoint, Vantage: req.Vantage, ObservedAt: req.ObservedAt,
			Reachable: req.Reachable, Health: req.Health, ServedFingerprint: req.ServedFingerprint,
			ChainFingerprints: req.ChainFingerprints, Detail: req.Detail,
		})
		if err != nil {
			return 0, nil, mapObserverError(err)
		}
		return http.StatusCreated, toObservationResponse(observation), nil
	})
}

func (a *API) listObservations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	q := r.URL.Query()
	limit := 0
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be 1 to 500"))
			return
		}
		limit = n
	}
	observations, err := a.store.ListExternalObservations(r.Context(), tenantID, store.ExternalObservationFilter{
		ObserverID: q.Get("observer_id"), Endpoint: q.Get("endpoint"), Fingerprint: strings.ToLower(q.Get("fingerprint")), Limit: limit,
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := make([]observationResponse, 0, len(observations))
	for _, observation := range observations {
		out = append(out, toObservationResponse(observation))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
