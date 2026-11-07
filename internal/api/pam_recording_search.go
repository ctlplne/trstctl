// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
)

// A275: search across the tenant's session recordings — SSH commands and
// output, SQL statements and results, remote desktop indexes — with masked
// results; every search is recorded.

// PAMRecordingSearchQuery is one search: the text to find (3-200
// characters, case-insensitive), when the sessions began, an optional
// target, how many recordings to read and how many lines to return.
type PAMRecordingSearchQuery struct {
	Text                 string
	Since, Until         time.Time
	TargetType, TargetID string
	Sessions, Limit      int
}

// PAMRecordingSearchHit is one matching line of a recording, masked.
type PAMRecordingSearchHit struct {
	SessionID        string    `json:"session_id"`
	TargetType       string    `json:"target_type"`
	TargetID         string    `json:"target_id"`
	Subject          string    `json:"subject"`
	SessionStartedAt time.Time `json:"session_started_at"`
	AtMillis         int64     `json:"at_millis"`
	Conn             int       `json:"conn"`
	Source           string    `json:"source"`
	Kind             string    `json:"kind,omitempty"`
	Text             string    `json:"text"`
}

// PAMRecordingSearchResult is a search's matching lines, how many
// recordings it read, and whether a bound stopped it early.
type PAMRecordingSearchResult struct {
	Items            []PAMRecordingSearchHit `json:"items"`
	SessionsSearched int                     `json:"sessions_searched"`
	Truncated        bool                    `json:"truncated"`
}

// PAMRecordingSearchService searches recordings; the served broker
// implements it.
type PAMRecordingSearchService interface {
	SearchPAMRecordings(ctx context.Context, tenantID, actor string, q PAMRecordingSearchQuery) (PAMRecordingSearchResult, error)
}

func (a *API) pamRecordingSearchRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/access/recordings/search", opID: "searchPAMRecordings",
			summary: "Search the tenant's session recordings — SSH commands and output, SQL statements and results, remote desktop indexes — newest sessions first; results are masked and every search is recorded",
			handler: a.searchPAMRecordings, query: []param{
				{name: "q", typ: "string", desc: "the text to find, 3-200 characters, case-insensitive"},
				{name: "since", typ: "string", desc: "sessions begun at or after this RFC 3339 time (default: 30 days ago)"},
				{name: "until", typ: "string", desc: "sessions begun before this RFC 3339 time (default: now)"},
				{name: "target_type", typ: "string", desc: "only this target type's sessions"},
				{name: "target_id", typ: "string", desc: "only this target's sessions"},
				{name: "sessions", typ: "integer", desc: "recordings to read, newest first, 1-200 (default 50)"},
				{name: "limit", typ: "integer", desc: "matching lines to return, 1-500 (default 100)"}},
			resSchema: "PAMRecordingSearchResult", successCode: "200", sensitiveResponse: true, perm: authz.RecordingsRead},
	}
}

func (a *API) searchPAMRecordings(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.pam.(PAMRecordingSearchService)
	if a.pam == nil || !ok {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "session recordings are not enabled"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	q := r.URL.Query()
	query := PAMRecordingSearchQuery{Text: strings.TrimSpace(q.Get("q")), TargetType: strings.TrimSpace(q.Get("target_type")),
		TargetID: strings.TrimSpace(q.Get("target_id")), Sessions: 50, Limit: 100}
	if n := len([]rune(query.Text)); n < 3 || n > 200 {
		a.writeError(w, errStatus(http.StatusBadRequest, "q must be 3-200 characters"))
		return
	}
	for _, p := range []struct {
		name     string
		into     *int
		min, max int
	}{{"sessions", &query.Sessions, 1, 200}, {"limit", &query.Limit, 1, 500}} {
		if raw := strings.TrimSpace(q.Get(p.name)); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < p.min || n > p.max {
				a.writeError(w, errStatus(http.StatusBadRequest, p.name+" must be "+strconv.Itoa(p.min)+"-"+strconv.Itoa(p.max)))
				return
			}
			*p.into = n
		}
	}
	now := time.Now().UTC()
	query.Since, query.Until = now.Add(-30*24*time.Hour), now
	for _, p := range []struct {
		name string
		into *time.Time
	}{{"since", &query.Since}, {"until", &query.Until}} {
		if raw := strings.TrimSpace(q.Get(p.name)); raw != "" {
			at, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				a.writeError(w, errStatus(http.StatusBadRequest, p.name+" must be an RFC 3339 time"))
				return
			}
			*p.into = at.UTC()
		}
	}
	if !query.Since.Before(query.Until) {
		a.writeError(w, errStatus(http.StatusBadRequest, "since must be before until"))
		return
	}
	out, err := svc.SearchPAMRecordings(r.Context(), tenantID, principalSubject(r.Context()), query)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}
