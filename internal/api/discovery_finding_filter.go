// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/store"
)

// Findings filters and dashboard pages (A105). The findings list narrows by
// run, source kind, finding kind and triage status on the server; the CT-log
// and drift dashboards page one source kind's findings and count all of them,
// so an operator never reads a first-page sample as the whole posture.

// discoveryTriageStatuses are the triage statuses a filter accepts.
var discoveryTriageStatuses = map[string]bool{
	string(discovery.TriageUnmanaged): true, string(discovery.TriageInvestigating): true,
	string(discovery.TriageManaged): true, string(discovery.TriageDismissed): true,
	string(discovery.TriageRemediated): true, string(discovery.TriageAcceptedRisk): true,
}

var discoveryFilterKind = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,127}$`)

func discoveryTriageFilter(raw string) (string, error) {
	status := strings.TrimSpace(raw)
	if status != "" && !discoveryTriageStatuses[status] {
		return "", errors.New("triage_status must be unmanaged, investigating, managed, dismissed, remediated or accepted_risk")
	}
	return status, nil
}

// discoveryFindingFilterFromQuery reads a findings list's filters.
func discoveryFindingFilterFromQuery(r *http.Request) (store.DiscoveryFindingFilter, error) {
	q := r.URL.Query()
	filter := store.DiscoveryFindingFilter{
		RunID:      strings.TrimSpace(q.Get("run_id")),
		SourceKind: strings.TrimSpace(q.Get("source_kind")),
		Kind:       strings.TrimSpace(q.Get("kind")),
	}
	if filter.RunID != "" {
		if _, err := googleuuid.Parse(filter.RunID); err != nil {
			return filter, errors.New("run_id must be a UUID")
		}
	}
	for _, field := range []struct{ name, value string }{{"source_kind", filter.SourceKind}, {"kind", filter.Kind}} {
		if field.value != "" && !discoveryFilterKind.MatchString(field.value) {
			return filter, fmt.Errorf("%s must be a lowercase kind name", field.name)
		}
	}
	filter.DistrustEntry = strings.TrimSpace(q.Get("distrust_entry"))
	if len(filter.DistrustEntry) > 256 {
		return filter, errors.New("distrust_entry must be at most 256 characters")
	}
	filter.KeyStrength = strings.TrimSpace(q.Get("key_strength"))
	if filter.KeyStrength != "" && filter.KeyStrength != "weak" {
		return filter, errors.New("key_strength must be weak")
	}
	status, err := discoveryTriageFilter(q.Get("triage_status"))
	filter.TriageStatus = status
	return filter, err
}

// discoveryDashboardPage is one page of a dashboard's findings.
type discoveryDashboardPage struct {
	TriageStatus string
	After        string
	Limit        int
}

// firstDiscoveryDashboardPage is what a dashboard shows first, and what a
// mutation's response carries.
var firstDiscoveryDashboardPage = discoveryDashboardPage{After: store.ZeroUUID, Limit: 50}

// discoveryDashboardPageFromQuery reads a dashboard page: triage_status,
// cursor and limit (1-100, default 50).
func discoveryDashboardPageFromQuery(r *http.Request) (discoveryDashboardPage, error) {
	page := firstDiscoveryDashboardPage
	q := r.URL.Query()
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			return page, errors.New("limit must be an integer between 1 and 100")
		}
		page.Limit = n
	}
	if raw := q.Get("cursor"); raw != "" {
		id, err := decodeCursor(raw)
		if err != nil {
			return page, errors.New("invalid cursor")
		}
		page.After = id
	}
	status, err := discoveryTriageFilter(q.Get("triage_status"))
	page.TriageStatus = status
	return page, err
}

// dashboardFindingsPage reads one page of a filter's findings, narrowed by
// the page's triage status, and the cursor of the next page.
func (a *API) dashboardFindingsPage(ctx context.Context, tenantID string, filter store.DiscoveryFindingFilter, page discoveryDashboardPage) ([]store.DiscoveryFinding, string, error) {
	filter.TriageStatus = page.TriageStatus
	rows, err := a.store.ListDiscoveryFindingsFiltered(ctx, tenantID, filter, page.After, page.Limit)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) == page.Limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	return rows, next, nil
}
