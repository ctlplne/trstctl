package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

type privacySubjectErasureRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

type privacySubjectErasureResponse struct {
	SubjectRef     string                        `json:"subject_ref"`
	RequestedByRef string                        `json:"requested_by_ref,omitempty"`
	Reason         string                        `json:"reason,omitempty"`
	Selectors      store.PrivacyErasureSelectors `json:"selectors"`
	Counts         map[string]int                `json:"counts"`
	ErasedAt       time.Time                     `json:"erased_at"`
}

type privacySubjectErasureListResponse struct {
	Items      []privacySubjectErasureResponse `json:"items"`
	NextCursor string                          `json:"next_cursor,omitempty"`
}

type privacyCatalogResponse struct {
	Items []privacy.CatalogEntry `json:"items"`
}

func toPrivacySubjectErasureResponse(e store.PrivacySubjectErasure) privacySubjectErasureResponse {
	counts := e.Counts
	if counts == nil {
		counts = map[string]int{}
	}
	return privacySubjectErasureResponse{
		SubjectRef:     e.SubjectRef,
		RequestedByRef: e.RequestedByRef,
		Reason:         e.Reason,
		Selectors:      e.Selectors,
		Counts:         counts,
		ErasedAt:       e.ErasedAt,
	}
}

//trstctl:mutation
func (a *API) erasePrivacySubject(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req privacySubjectErasureRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Subject = strings.TrimSpace(req.Subject)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.Subject == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "subject is required")
		}
		erasure, err := a.orch.ErasePrivacySubject(ctx, tenantID, req.Subject, req.Reason)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toPrivacySubjectErasureResponse(erasure), nil
	})
}

func (a *API) listPrivacySubjectErasures(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	after := ""
	if c := r.URL.Query().Get("cursor"); c != "" {
		after, err = decodeStringCursor(c)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
	}
	erasures, err := a.store.ListPrivacySubjectErasuresPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]privacySubjectErasureResponse, 0, len(erasures))
	for _, erasure := range erasures {
		items = append(items, toPrivacySubjectErasureResponse(erasure))
	}
	next := ""
	if len(erasures) == limit {
		next = encodeStringCursor(erasures[len(erasures)-1].SubjectRef)
	}
	a.writeJSON(w, http.StatusOK, privacySubjectErasureListResponse{Items: items, NextCursor: next})
}

func (a *API) getPrivacyCatalog(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, http.StatusOK, privacyCatalogResponse{Items: privacy.Catalog()})
}

func encodeStringCursor(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeStringCursor(cursor string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("empty cursor")
	}
	return string(b), nil
}
