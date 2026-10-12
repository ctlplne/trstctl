// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api/problem"
)

func (a *API) listBreakglassIssues(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "emergency issue read model is unavailable"))
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusBadRequest, err.Error()))
		return
	}
	var before uint64
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err == nil {
			before, err = strconv.ParseUint(string(raw), 10, 63)
		}
		if err != nil || before == 0 {
			a.writeProblem(w, problem.New(http.StatusBadRequest, "invalid emergency issue cursor"))
			return
		}
	}
	rows, err := a.store.ListBreakglassIssueReceipts(r.Context(), tenantID, before, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	next := ""
	if len(rows) == limit {
		next = base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(rows[len(rows)-1].EventSequence, 10)))
	}
	w.Header().Set("Cache-Control", "no-store")
	a.writeJSON(w, http.StatusOK, listResponse{Items: rows, NextCursor: next})
}

func (a *API) getBreakglassIssue(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "emergency issue read model is unavailable"))
		return
	}
	id := r.PathValue("id")
	if _, err := googleuuid.Parse(id); err != nil {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "invalid ceremony ID"))
		return
	}
	rec, err := a.store.GetBreakglassIssueReceipt(r.Context(), tenantID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		a.writeProblem(w, problem.New(http.StatusNotFound, "emergency issue receipt not found"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.writeJSON(w, http.StatusOK, rec)
}
