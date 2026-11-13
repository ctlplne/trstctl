// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/store"
)

// The served misuse findings (M2-L1). Detection records every finding in the
// misuse_findings read model, but raises an alert only within the tenant's
// hourly budget; this route lists the caller's own tenant's findings, newest
// first, so a finding whose alert was capped is still read where it stands.

const (
	findingsDefaultLimit   = 50
	findingsMaxLimit       = 200
	findingsMaxCredentialB = 128
)

// Finding is one served misuse finding. Sequence is the event that recorded
// it, which orders and pages the listing.
type Finding struct {
	ID            string    `json:"id"`
	Rule          string    `json:"rule"`
	CredentialID  string    `json:"credential_id"`
	Principal     string    `json:"principal"`
	Source        string    `json:"source"`
	WindowStart   time.Time `json:"window_start"`
	ObservedCount int       `json:"observed_count"`
	Baseline      int       `json:"baseline"`
	Alerted       bool      `json:"alerted"`
	DetectedAt    time.Time `json:"detected_at"`
	Sequence      int64     `json:"-"`
}

// FindingList is one page of findings; NextCursor is empty on the last page.
type FindingList struct {
	Items      []Finding `json:"items"`
	NextCursor string    `json:"next_cursor"`
}

// FindingFilter narrows a listing: one rule, one credential, and the event
// sequence a page starts below (0 for the newest), at most Limit rows.
type FindingFilter struct {
	Rule         string
	CredentialID string
	Before       int64
	Limit        int
}

// FindingReader reads one tenant's findings, newest first.
type FindingReader interface {
	ListFindings(ctx context.Context, tenantID string, filter FindingFilter) ([]Finding, error)
}

// StoreFindings reads the misuse_findings read model under the tenant's
// row-level security.
type StoreFindings struct{ Store *store.Store }

// ListFindings implements FindingReader.
func (s StoreFindings) ListFindings(ctx context.Context, tenantID string, filter FindingFilter) ([]Finding, error) {
	out := []Finding{}
	err := s.Store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT finding_id, rule, credential_id, principal, source, window_start, observed_count,
			       baseline, alerted, detected_at, event_sequence
			FROM misuse_findings
			WHERE tenant_id = $1
			  AND ($2::text = '' OR rule = $2::text)
			  AND ($3::text = '' OR credential_id = $3::text)
			  AND ($4::bigint = 0 OR event_sequence < $4::bigint)
			ORDER BY event_sequence DESC
			LIMIT $5`, tenantID, filter.Rule, filter.CredentialID, filter.Before, filter.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f Finding
			if err := rows.Scan(&f.ID, &f.Rule, &f.CredentialID, &f.Principal, &f.Source, &f.WindowStart,
				&f.ObservedCount, &f.Baseline, &f.Alerted, &f.DetectedAt, &f.Sequence); err != nil {
				return err
			}
			f.WindowStart, f.DetectedAt = f.WindowStart.UTC(), f.DetectedAt.UTC()
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// Routes is the served findings surface.
func Routes(reader FindingReader) []api.LicensedRoute {
	return []api.LicensedRoute{{
		Method:      http.MethodGet,
		Path:        "/api/v1/misuse/findings",
		OperationID: "listMisuseFindings",
		Summary:     "Misuse findings: a token's lease from a new network, or a burst of its secret reads",
		Query: []api.RouteParam{
			{Name: "rule", Type: "string", Description: "new_source_lease or secret_read_burst"},
			{Name: "credential_id", Type: "string", Description: "one API token's findings"},
			{Name: "limit", Type: "integer", Description: "page size, 1-200 (default 50)"},
			{Name: "cursor", Type: "string", Description: "opaque cursor from the previous page"},
		},
		Handler: func(a *api.API) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { serveFindings(a, w, r, reader) }
		},
		ResponseSchema: "MisuseFindingList",
		SuccessCode:    "200",
		// audit:read: a finding is a record of what a tenant's tokens did, and
		// the people who may read that are the people who may read this.
		Permission: authz.AuditRead,
	}}
}

// PolicyService reads and sets a tenant's misuse detection policy (M2-L2).
type PolicyService interface {
	Get(ctx context.Context, tenantID string) (PolicyView, error)
	Set(ctx context.Context, tenantID string, pol Policy) (PolicyView, error)
}

// PolicyRoutes is the served policy surface (M2-L2): any caller who may read
// policy sees the thresholds detection uses, and one who may write policy
// sets them.
func PolicyRoutes(policies PolicyService) []api.LicensedRoute {
	return []api.LicensedRoute{{
		Method:      http.MethodGet,
		Path:        "/api/v1/misuse/policy",
		OperationID: "getMisusePolicy",
		Summary:     "The thresholds misuse detection uses for this tenant: its own, or the defaults",
		Handler: func(a *api.API) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { servePolicy(a, w, r, policies) }
		},
		ResponseSchema: "MisusePolicy",
		SuccessCode:    "200",
		Permission:     authz.PolicyRead,
	}, {
		Method:        http.MethodPut,
		Path:          "/api/v1/misuse/policy",
		OperationID:   "setMisusePolicy",
		Summary:       "Set the thresholds misuse detection uses for this tenant",
		RequestSchema: "MisusePolicyRequest",
		Handler: func(a *api.API) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { setPolicy(a, w, r, policies) }
		},
		ResponseSchema: "MisusePolicy",
		SuccessCode:    "200",
		Mutation:       true,
		Permission:     authz.PolicyWrite,
	}}
}

// NewAPIOptionsFactory mounts the findings and policy routes behind the
// Enterprise seam.
func NewAPIOptionsFactory(reader FindingReader) editionseam.LicensedAPIOptionsFactory {
	return func(deps editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		policies := PolicyStore{Store: deps.Store, Log: deps.Log, Defaults: DefaultPolicy(0)}
		incidents := IncidentStore{Store: deps.Store, Log: deps.Log}
		routes := append(append(Routes(reader), PolicyRoutes(policies)...), IncidentRoutes(incidents)...)
		return []api.Option{
			api.WithLicensedRoutes(routes...),
			api.WithLicensedSchemas(findingSchemas()),
			api.WithLicensedSchemas(policySchemas()),
			api.WithLicensedSchemas(incidentSchemas()),
		}, nil
	}
}

func servePolicy(a *api.API, w http.ResponseWriter, r *http.Request, policies PolicyService) {
	tenantID, ok := a.Tenant(r)
	if !ok || strings.TrimSpace(tenantID) == "" {
		a.WriteProblemUnauthorized(w)
		return
	}
	view, err := policies.Get(r.Context(), tenantID)
	if err != nil {
		a.WriteError(w, err)
		return
	}
	a.WriteJSON(w, http.StatusOK, view)
}

func setPolicy(a *api.API, w http.ResponseWriter, r *http.Request, policies PolicyService) {
	a.Mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var pol Policy
		if err := api.DecodeJSONStrict(r, &pol); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if err := pol.Validate(); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		view, err := policies.Set(ctx, tenantID, pol)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, view, nil
	})
}

func policySchemas() map[string]*api.Schema {
	integer := func(desc string) *api.Schema { return &api.Schema{Type: "integer", Description: desc} }
	fields := map[string]*api.Schema{
		"normal_days":         integer("a lease from a network the token has not used on this many different days is new (1-30; default 3)"),
		"burst_floor":         integer("an hour of at least this many secret reads can be a burst (1-100000; default 64)"),
		"burst_factor":        integer("and at least this many times the token's largest earlier hour (2-100; default 4)"),
		"burst_lookback_days": integer("the earlier hours looked at, in days (1-90; default 14)"),
		"hourly_alert_cap":    integer("at most this many findings an hour alert (1-1000; default 20)"),
	}
	required := []string{"normal_days", "burst_floor", "burst_factor", "burst_lookback_days", "hourly_alert_cap"}
	view := map[string]*api.Schema{"custom": {Type: "boolean", Description: "false when the defaults apply"},
		"set_by": {Type: "string"}, "updated_at": {Type: "string", Format: "date-time"}}
	for k, v := range fields {
		view[k] = v
	}
	return map[string]*api.Schema{
		"MisusePolicyRequest": {Type: "object", Description: "M2-L2: a tenant's misuse detection thresholds.", Properties: fields, Required: required},
		"MisusePolicy": {Type: "object", Description: "M2-L2: the thresholds misuse detection uses for this tenant.", Properties: view,
			Required: append(append([]string{}, required...), "custom")},
	}
}

func serveFindings(a *api.API, w http.ResponseWriter, r *http.Request, reader FindingReader) {
	// The caller's own tenancy only: nothing in the query names a tenant.
	tenantID, ok := a.Tenant(r)
	if !ok || strings.TrimSpace(tenantID) == "" {
		a.WriteProblemUnauthorized(w)
		return
	}
	q := r.URL.Query()
	filter := FindingFilter{Rule: strings.TrimSpace(q.Get("rule")), CredentialID: strings.TrimSpace(q.Get("credential_id")), Limit: findingsDefaultLimit}
	if filter.Rule != "" && filter.Rule != RuleNewSourceLease && filter.Rule != RuleSecretReadBurst {
		a.WriteError(w, api.ErrStatus(http.StatusBadRequest, "rule must be new_source_lease or secret_read_burst"))
		return
	}
	if len(filter.CredentialID) > findingsMaxCredentialB {
		a.WriteError(w, api.ErrStatus(http.StatusBadRequest, "credential_id is longer than any API token ID"))
		return
	}
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > findingsMaxLimit {
			a.WriteError(w, api.ErrStatus(http.StatusBadRequest, "limit must be 1-200"))
			return
		}
		filter.Limit = n
	}
	if raw := strings.TrimSpace(q.Get("cursor")); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			a.WriteError(w, api.ErrStatus(http.StatusBadRequest, "cursor is not one this route returned"))
			return
		}
		filter.Before = n
	}
	page := filter
	page.Limit = filter.Limit + 1
	items, err := reader.ListFindings(r.Context(), tenantID, page)
	if err != nil {
		a.WriteError(w, err)
		return
	}
	list := FindingList{Items: []Finding{}}
	if len(items) > filter.Limit {
		items = items[:filter.Limit]
		list.NextCursor = strconv.FormatInt(items[len(items)-1].Sequence, 10)
	}
	list.Items = append(list.Items, items...)
	a.WriteJSON(w, http.StatusOK, list)
}

func findingSchemas() map[string]*api.Schema {
	str := func() *api.Schema { return &api.Schema{Type: "string"} }
	stamp := func() *api.Schema { return &api.Schema{Type: "string", Format: "date-time"} }
	return map[string]*api.Schema{
		"MisuseFinding": {
			Type: "object",
			Description: "M2: one misuse finding, one per API token, rule and day. new_source_lease: the token requested a " +
				"dynamic-secret lease from a client network it had not used on three days while it has one it has; " +
				"secret_read_burst: an hour of at least 64 secret reads and four times the token's largest earlier hour " +
				"in 14 days (baseline). alerted is false when the tenant's hourly alert budget was spent.",
			Properties: map[string]*api.Schema{
				"id": str(), "rule": {Type: "string", Enum: []string{RuleNewSourceLease, RuleSecretReadBurst}},
				"credential_id": str(), "principal": str(), "source": str(), "window_start": stamp(),
				"observed_count": {Type: "integer"}, "baseline": {Type: "integer"}, "alerted": {Type: "boolean"},
				"detected_at": stamp(),
			},
			Required: []string{"id", "rule", "credential_id", "principal", "source", "window_start", "observed_count", "baseline", "alerted", "detected_at"},
		},
		"MisuseFindingList": {
			Type: "object",
			Properties: map[string]*api.Schema{
				"items":       {Type: "array", Items: &api.Schema{Ref: "#/components/schemas/MisuseFinding"}},
				"next_cursor": str(),
			},
			Required: []string{"items", "next_cursor"},
		},
	}
}

// IncidentService lists and closes a tenant's misuse incidents (M2-L3).
type IncidentService interface {
	List(ctx context.Context, tenantID, status string, limit int) ([]Incident, error)
	Close(ctx context.Context, tenantID, incidentID, resolution, note string) (Incident, error)
}

// IncidentList is a page of misuse incidents.
type IncidentList struct {
	Items []Incident `json:"items"`
}

// IncidentRoutes is the served incident surface (M2-L3).
func IncidentRoutes(incidents IncidentService) []api.LicensedRoute {
	return []api.LicensedRoute{{
		Method:      http.MethodGet,
		Path:        "/api/v1/misuse/incidents",
		OperationID: "listMisuseIncidents",
		Summary:     "Misuse incidents: one per API token a finding flagged, open until closed with a resolution",
		Query: []api.RouteParam{
			{Name: "status", Type: "string", Description: "open or closed"},
			{Name: "limit", Type: "integer", Description: "page size, 1-200 (default 50)"},
		},
		Handler: func(a *api.API) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { serveIncidents(a, w, r, incidents) }
		},
		ResponseSchema: "MisuseIncidentList",
		SuccessCode:    "200",
		Permission:     authz.IncidentsRead,
	}, {
		Method:        http.MethodPost,
		Path:          "/api/v1/misuse/incidents/{id}/close",
		OperationID:   "closeMisuseIncident",
		Summary:       "Close a misuse incident with its resolution",
		PathParams:    []api.RouteParam{{Name: "id", Type: "string", Description: "incident id"}},
		RequestSchema: "MisuseIncidentCloseRequest",
		Handler: func(a *api.API) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { closeIncident(a, w, r, incidents) }
		},
		ResponseSchema: "MisuseIncident",
		SuccessCode:    "200",
		Mutation:       true,
		Permission:     authz.IncidentsWrite,
	}}
}

func serveIncidents(a *api.API, w http.ResponseWriter, r *http.Request, incidents IncidentService) {
	tenantID, ok := a.Tenant(r)
	if !ok || strings.TrimSpace(tenantID) == "" {
		a.WriteProblemUnauthorized(w)
		return
	}
	q := r.URL.Query()
	status := strings.TrimSpace(q.Get("status"))
	if status != "" && status != "open" && status != "closed" {
		a.WriteError(w, api.ErrStatus(http.StatusBadRequest, "status must be open or closed"))
		return
	}
	limit := findingsDefaultLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxIncidentList {
			a.WriteError(w, api.ErrStatus(http.StatusBadRequest, "limit must be 1-200"))
			return
		}
		limit = n
	}
	items, err := incidents.List(r.Context(), tenantID, status, limit)
	if err != nil {
		a.WriteError(w, err)
		return
	}
	a.WriteJSON(w, http.StatusOK, IncidentList{Items: append([]Incident{}, items...)})
}

func closeIncident(a *api.API, w http.ResponseWriter, r *http.Request, incidents IncidentService) {
	a.Mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var body struct {
			Resolution string `json:"resolution"`
			Note       string `json:"note,omitempty"`
		}
		if err := api.DecodeJSONStrict(r, &body); err != nil {
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		if !validResolution(body.Resolution) {
			return 0, nil, api.ErrStatus(http.StatusBadRequest, "resolution must be token_revoked, expected_use or other")
		}
		in, err := incidents.Close(ctx, tenantID, r.PathValue("id"), body.Resolution, body.Note)
		switch {
		case errors.Is(err, ErrIncidentNotFound):
			return 0, nil, api.ErrStatus(http.StatusNotFound, "no such misuse incident")
		case errors.Is(err, ErrIncidentNotOpen):
			return 0, nil, api.ErrStatus(http.StatusConflict, "the incident is already closed")
		case err != nil:
			return 0, nil, api.ErrWithStatus(http.StatusBadRequest, err)
		}
		return http.StatusOK, in, nil
	})
}

func incidentSchemas() map[string]*api.Schema {
	str := func() *api.Schema { return &api.Schema{Type: "string"} }
	stamp := func() *api.Schema { return &api.Schema{Type: "string", Format: "date-time"} }
	resolution := &api.Schema{Type: "string", Enum: []string{ResolutionTokenRevoked, ResolutionExpectedUse, ResolutionOther}}
	return map[string]*api.Schema{
		"MisuseIncident": {
			Type: "object",
			Description: "M2-L3: the incident a misuse finding opened for its API token. findings counts the token's " +
				"findings from the opening to the close (or now).",
			Properties: map[string]*api.Schema{
				"id": str(), "credential_id": str(), "principal": str(),
				"status": {Type: "string", Enum: []string{"open", "closed"}}, "opened_at": stamp(),
				"findings": {Type: "integer"}, "closed_at": stamp(), "closed_by": str(), "resolution": resolution, "note": str(),
			},
			Required: []string{"id", "credential_id", "principal", "status", "opened_at", "findings"},
		},
		"MisuseIncidentList": {
			Type:       "object",
			Properties: map[string]*api.Schema{"items": {Type: "array", Items: &api.Schema{Ref: "#/components/schemas/MisuseIncident"}}},
			Required:   []string{"items"},
		},
		"MisuseIncidentCloseRequest": {
			Type:       "object",
			Properties: map[string]*api.Schema{"resolution": resolution, "note": {Type: "string", Description: "at most 500 characters"}},
			Required:   []string{"resolution"},
		},
	}
}
