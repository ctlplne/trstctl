// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

type brokerHistoryItem struct {
	CertificateID      string                `json:"certificate_id"`
	Fingerprint        string                `json:"fingerprint"`
	CertificateSubject string                `json:"certificate_subject"`
	Serial             string                `json:"serial"`
	CurrentOwnerID     *string               `json:"current_owner_id,omitempty"`
	NotBefore          *time.Time            `json:"not_before,omitempty"`
	NotAfter           *time.Time            `json:"not_after,omitempty"`
	RecordedAt         time.Time             `json:"recorded_at"`
	LifecycleStatus    string                `json:"lifecycle_status"`
	State              string                `json:"state"`
	StateReason        string                `json:"state_reason"`
	MetadataState      string                `json:"metadata_state"`
	Issuance           *store.BrokerIssuance `json:"issuance,omitempty"`
	GeneratedAt        time.Time             `json:"generated_at"`
	ProjectionState    string                `json:"projection_state"`
}

type brokerHistoryPage struct {
	Items           []brokerHistoryItem `json:"items"`
	NextCursor      string              `json:"next_cursor"`
	GeneratedAt     time.Time           `json:"generated_at"`
	ProjectionState string              `json:"projection_state"`
	HistoryScope    string              `json:"history_scope"`
}

type brokerHistoryCursor struct {
	RecordedAt time.Time `json:"at"`
	ID         string    `json:"id"`
}

func brokerHistoryParams(r *http.Request) (store.BrokerHistoryFilter, int, error) {
	limit, err := pageLimit(r)
	if err != nil {
		return store.BrokerHistoryFilter{}, 0, err
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return store.BrokerHistoryFilter{}, 0, errors.New("invalid broker history query encoding")
	}
	for key, entries := range values {
		if !slices.Contains([]string{"limit", "cursor", "q", "method", "state"}, key) || len(entries) != 1 {
			return store.BrokerHistoryFilter{}, 0, errors.New("broker history accepts one limit, cursor, q, method and state value")
		}
	}
	f := store.BrokerHistoryFilter{AfterID: store.ZeroUUID, Limit: limit + 1, Query: strings.TrimSpace(values.Get("q")), Method: strings.TrimSpace(values.Get("method")), State: values.Get("state")}
	if utf8.RuneCountInString(f.Query) > 200 || utf8.RuneCountInString(f.Method) > 128 {
		return f, 0, errors.New("history search is limited to 200 characters and method to 128")
	}
	if f.State != "" && !slices.Contains(store.BrokerCertificateStates(), f.State) {
		return f, 0, errors.New("unknown broker certificate state")
	}
	if raw := values.Get("cursor"); raw != "" {
		if len(raw) > 512 {
			return f, 0, errors.New("invalid broker history cursor")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return f, 0, errors.New("invalid broker history cursor")
		}
		var cursor brokerHistoryCursor
		decoder := json.NewDecoder(bytes.NewReader(decoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cursor); err != nil {
			return f, 0, errors.New("invalid broker history cursor")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return f, 0, errors.New("invalid broker history cursor")
		}
		id, err := googleuuid.Parse(cursor.ID)
		if err != nil || id.String() != cursor.ID || cursor.RecordedAt.IsZero() {
			return f, 0, errors.New("invalid broker history cursor")
		}
		f.AfterTime, f.AfterID = &cursor.RecordedAt, cursor.ID
	}
	return f, limit, nil
}

func (a *API) listBrokerAgentIdentities(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "certificate inventory is unavailable"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	f, limit, err := brokerHistoryParams(r)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	now := time.Now().UTC()
	projectionState := a.brokerHistoryProjectionState(r.Context())
	rows, err := a.store.ListBrokerCertificatesPage(r.Context(), tenantID, f, now)
	if err != nil {
		a.writeError(w, err)
		return
	}
	next := ""
	if len(rows) > limit {
		last := rows[limit-1]
		cursor, err := json.Marshal(brokerHistoryCursor{RecordedAt: last.RecordedAt, ID: last.CertificateID})
		if err != nil {
			a.writeError(w, err)
			return
		}
		next = base64.RawURLEncoding.EncodeToString(cursor)
		rows = rows[:limit]
	}
	items := make([]brokerHistoryItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, brokerHistoryResponse(row, now, projectionState))
	}
	a.writeJSON(w, http.StatusOK, brokerHistoryPage{Items: items, NextCursor: next, GeneratedAt: now, ProjectionState: projectionState, HistoryScope: "broker_issued_certificates"})
}

func (a *API) getBrokerAgentIdentity(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "certificate inventory is unavailable"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id, err := googleuuid.Parse(r.PathValue("id"))
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "certificate ID must be a UUID"))
		return
	}
	now := time.Now().UTC()
	projectionState := a.brokerHistoryProjectionState(r.Context())
	row, err := a.store.GetBrokerCertificate(r.Context(), tenantID, id.String(), now)
	if errors.Is(err, pgx.ErrNoRows) {
		a.writeError(w, errStatus(http.StatusNotFound, "no broker certificate found"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, brokerHistoryResponse(row, now, projectionState))
}

func brokerHistoryResponse(row store.BrokerCertificate, now time.Time, projectionState string) brokerHistoryItem {
	reason := map[string]string{
		"valid":         "The certificate is within its validity window and its projected lifecycle is active. Check projection freshness; receiving services still enforce access policy.",
		"not_yet_valid": "The certificate validity window has not started. Do not use it before NotBefore.",
		"expired":       "The certificate has reached NotAfter. A new credential is needed; retrying the old command does not renew it.",
		"revoked":       "The shared certificate inventory records a revocation. Do not use this credential.",
		"superseded":    "A successor replaced this certificate. Use and verify the successor, not this historical credential.",
		"unknown":       "Lifecycle or validity evidence is incomplete or inconsistent. Do not assume this credential is usable.",
	}[row.State]
	metadataState := "unavailable"
	if row.Issuance != nil {
		metadataState = "recorded"
	}
	return brokerHistoryItem{CertificateID: row.CertificateID, Fingerprint: row.Fingerprint, CertificateSubject: row.CertificateSubject,
		Serial: row.Serial, CurrentOwnerID: row.CurrentOwnerID, NotBefore: row.NotBefore, NotAfter: row.NotAfter, RecordedAt: row.RecordedAt,
		LifecycleStatus: row.Status, State: row.State, StateReason: reason, MetadataState: metadataState, Issuance: row.Issuance, GeneratedAt: now, ProjectionState: projectionState}
}

// Expose only coarse projection health, never another tenant's event counts or
// raw failure details. Read the watermark BEFORE the data query so lag can be
// conservative but cannot describe an older data query as caught up afterward.
func (a *API) brokerHistoryProjectionState(ctx context.Context) string {
	if a.log == nil {
		return "unknown"
	}
	head, err := a.log.LastSequence(ctx)
	if err != nil {
		return "unknown"
	}
	health, err := a.store.ProjectionTailHealth(ctx)
	if err != nil {
		return "unknown"
	}
	if health.FailedSequence != 0 {
		return "blocked"
	}
	if health.AppliedSequence < head {
		return "catching_up"
	}
	return "current"
}
