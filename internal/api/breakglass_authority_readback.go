// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/store"
)

type BreakglassAuthorityReceipt struct {
	TenantID      string               `json:"tenant_id"`
	CeremonyID    string               `json:"ceremony_id"`
	Kind          string               `json:"kind"`
	Subject       string               `json:"subject"`
	RequestDigest string               `json:"request_digest"`
	EventSequence uint64               `json:"event_sequence"`
	CompletedAt   time.Time            `json:"completed_at"`
	Rotation      *BreakglassRotation  `json:"rotation,omitempty"`
	CrossSign     *BreakglassCrossSign `json:"cross_sign,omitempty"`
}

func authorityReceiptResponse(rec store.BreakglassAuthorityReceipt) (BreakglassAuthorityReceipt, error) {
	result := BreakglassAuthorityReceipt{
		TenantID: rec.TenantID, CeremonyID: rec.CeremonyID, Kind: rec.Kind,
		Subject: rec.Subject, RequestDigest: rec.RequestDigest,
		EventSequence: rec.EventSequence, CompletedAt: rec.CompletedAt,
	}
	if len(rec.Result) == 0 {
		return result, nil
	}
	switch rec.Kind {
	case "rotation":
		var rotation BreakglassRotation
		if err := json.Unmarshal(rec.Result, &rotation); err != nil {
			return result, err
		}
		result.Rotation = &rotation
	case "cross_sign":
		var cross BreakglassCrossSign
		if err := json.Unmarshal(rec.Result, &cross); err != nil {
			return result, err
		}
		result.CrossSign = &cross
	default:
		return result, errors.New("unknown break-glass authority receipt kind")
	}
	return result, nil
}

func (a *API) listBreakglassAuthorityReceipts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "emergency authority read model is unavailable"))
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusBadRequest, err.Error()))
		return
	}
	var before uint64
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		raw, decodeErr := base64.RawURLEncoding.DecodeString(cursor)
		if decodeErr == nil {
			before, decodeErr = strconv.ParseUint(string(raw), 10, 63)
		}
		if decodeErr != nil || before == 0 {
			a.writeProblem(w, problem.New(http.StatusBadRequest, "invalid emergency authority cursor"))
			return
		}
	}
	rows, err := a.store.ListBreakglassAuthorityReceipts(r.Context(), tenantID, before, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]BreakglassAuthorityReceipt, 0, len(rows))
	for _, row := range rows {
		item, err := authorityReceiptResponse(row)
		if err != nil {
			a.writeError(w, err)
			return
		}
		items = append(items, item)
	}
	next := ""
	if len(rows) == limit {
		next = base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(rows[len(rows)-1].EventSequence, 10)))
	}
	w.Header().Set("Cache-Control", "no-store")
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getBreakglassAuthorityReceipt(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "emergency authority read model is unavailable"))
		return
	}
	id := r.PathValue("id")
	if _, err := googleuuid.Parse(id); err != nil {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "invalid ceremony ID"))
		return
	}
	rec, err := a.store.GetBreakglassAuthorityReceipt(r.Context(), tenantID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		a.writeProblem(w, problem.New(http.StatusNotFound, "emergency authority receipt not found"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	result, err := authorityReceiptResponse(rec)
	if err != nil {
		a.writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.writeJSON(w, http.StatusOK, result)
}
