// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

// The ticket intake schedule (I3): the ITSM's tickets become issuance
// requests, with the existing lifecycle deciding them.

type ticketIntakeBody struct {
	System      string `json:"system"`
	InstanceURL string `json:"instance_url"`
	TokenRef    string `json:"token_ref"`
	// SNTable is bounded to the request-shaped tables by the schema and
	// re-checked here so the operator learns the rule from the form.
	SNTable string `json:"sn_table"`
	// JiraProject is the closed project boundary for Jira searches.
	JiraProject string `json:"jira_project,omitempty"`
	Query       string `json:"query,omitempty"`
	// The field mapping is explicit, never inferred: an intake that guessed
	// which field holds the subject would open requests for prose.
	SubjectField         string   `json:"subject_field"`
	ProfileField         string   `json:"profile_field"`
	RequesterField       string   `json:"requester_field,omitempty"`
	JustificationField   string   `json:"justification_field,omitempty"`
	IntervalSeconds      int      `json:"interval_seconds"`
	Enabled              bool     `json:"enabled"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

type ticketIntakeResponse struct {
	Configured           bool     `json:"configured"`
	System               string   `json:"system,omitempty"`
	InstanceURL          string   `json:"instance_url,omitempty"`
	TokenRef             string   `json:"token_ref,omitempty"`
	SNTable              string   `json:"sn_table,omitempty"`
	JiraProject          string   `json:"jira_project,omitempty"`
	Query                string   `json:"query,omitempty"`
	SubjectField         string   `json:"subject_field,omitempty"`
	ProfileField         string   `json:"profile_field,omitempty"`
	RequesterField       string   `json:"requester_field,omitempty"`
	JustificationField   string   `json:"justification_field,omitempty"`
	IntervalSeconds      int      `json:"interval_seconds,omitempty"`
	Enabled              bool     `json:"enabled"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
	LastRunAt            string   `json:"last_run_at,omitempty"`
	SweepID              string   `json:"sweep_id,omitempty"`
	SweepStartedAt       string   `json:"sweep_started_at,omitempty"`
	LastAttemptAt        string   `json:"last_attempt_at,omitempty"`
	NextCursor           string   `json:"next_cursor,omitempty"`
	ReadCount            int      `json:"read_count"`
	ExpectedCount        *int     `json:"expected_count,omitempty"`
	PagesCompleted       int      `json:"pages_completed"`
	CoverageComplete     bool     `json:"coverage_complete"`
	EligibleCount        int      `json:"eligible_count"`
	SkippedCount         int      `json:"skipped_count"`
	LastError            string   `json:"last_error,omitempty"`
	Guidance             string   `json:"guidance"`
}

const ticketIntakeGuidance = "The intake reads the named ServiceNow table or Jira project on the tenant's interval " +
	"and opens one issuance request per ticket — idempotently by ticket reference, so a denied " +
	"request does not reopen (the denial WAS the answer; a fresh ask needs a fresh ticket). The " +
	"field mapping is explicit: tickets missing the mapped subject or profile are skipped and " +
	"counted, never guessed at. Requests carry the provider origin and exact ticket " +
	"reference, and the existing lifecycle — approval with separation of duties, denial with a " +
	"reason, expiry — decides them. The read is a durable ticket.sync job executed by a network " +
	"relay with per-attempt token redemption; the control plane never dials either provider. A named " +
	"sweep advances bounded pages and only its terminal page publishes complete coverage."

var ticketIntakeTables = map[string]bool{
	"incident": true, "sc_req_item": true, "sc_request": true, "change_request": true,
}

func (a *API) putTicketIntakeSchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body ticketIntakeBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		system := strings.TrimSpace(body.System)
		if system != ticketintake.SystemServiceNow && system != ticketintake.SystemJira {
			return 0, nil, errStatus(http.StatusBadRequest, "system must be servicenow or jira")
		}
		if err := requireAbsoluteURL(body.InstanceURL, "instance_url"); err != nil {
			return 0, nil, err
		}
		if !strings.HasPrefix(strings.TrimSpace(body.TokenRef), "secret://") {
			return 0, nil, errStatus(http.StatusBadRequest,
				"token_ref must be a secret:// reference redeemed by the network relay per attempt")
		}
		table, project := strings.TrimSpace(body.SNTable), strings.TrimSpace(body.JiraProject)
		if system == ticketintake.SystemServiceNow && !ticketIntakeTables[table] {
			return 0, nil, errStatus(http.StatusBadRequest,
				"sn_table must be one of incident, sc_req_item, sc_request, change_request — the "+
					"request-shaped tables; an unbounded table name would aim the intake token at "+
					"records that are not tickets")
		}
		if system == ticketintake.SystemServiceNow {
			project = ""
		} else {
			table = ""
		}
		if strings.TrimSpace(body.SubjectField) == "" || strings.TrimSpace(body.ProfileField) == "" {
			return 0, nil, errStatus(http.StatusBadRequest,
				"subject_field and profile_field are required; an intake that guessed which ticket "+
					"field holds the certificate subject would open requests for prose")
		}
		if body.IntervalSeconds < minCMDBInterval {
			return 0, nil, errStatus(http.StatusBadRequest,
				"interval_seconds must be at least 300")
		}
		if body.AllowPrivateEndpoint {
			return 0, nil, errStatus(http.StatusBadRequest,
				"allow_private_endpoint is a control-plane egress grant and is not valid for relay-only ticket intake")
		}
		if _, err := ticketintake.Endpoint(ticketintake.SyncIntent{
			System: system, InstanceURL: strings.TrimSpace(body.InstanceURL),
			SNTable: table, JiraProject: project, Query: strings.TrimSpace(body.Query),
			SubjectField: strings.TrimSpace(body.SubjectField), ProfileField: strings.TrimSpace(body.ProfileField),
			RequesterField: strings.TrimSpace(body.RequesterField), JustificationField: strings.TrimSpace(body.JustificationField),
			PageLimit: ticketintake.MaxTickets,
		}); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		saved := store.TicketIntakeSchedule{
			TenantID: tenantID, System: system,
			InstanceURL: strings.TrimSpace(body.InstanceURL),
			TokenRef:    strings.TrimSpace(body.TokenRef),
			SNTable:     table, JiraProject: project, Query: strings.TrimSpace(body.Query),
			SubjectField:       strings.TrimSpace(body.SubjectField),
			ProfileField:       strings.TrimSpace(body.ProfileField),
			RequesterField:     strings.TrimSpace(body.RequesterField),
			JustificationField: strings.TrimSpace(body.JustificationField),
			IntervalSeconds:    body.IntervalSeconds, Enabled: body.Enabled,
			AllowPrivateEndpoint: false,
			PrivateEgressCIDRs:   nil,
		}
		if err := a.orch.ConfigureTicketIntake(ctx, tenantID, projections.TicketIntakeConfigured{
			System: saved.System, InstanceURL: saved.InstanceURL, TokenRef: saved.TokenRef,
			SNTable: saved.SNTable, JiraProject: saved.JiraProject, Query: saved.Query,
			SubjectField: saved.SubjectField, ProfileField: saved.ProfileField,
			RequesterField: saved.RequesterField, JustificationField: saved.JustificationField,
			IntervalSeconds: saved.IntervalSeconds, Enabled: saved.Enabled,
			AllowPrivate: saved.AllowPrivateEndpoint, PrivateCIDRs: saved.PrivateEgressCIDRs,
		}); errors.Is(err, orchestrator.ErrTicketIntakeSweepInProgress) {
			return 0, nil, errStatus(http.StatusConflict,
				"the current ticket-intake sweep is incomplete; wait for its retained cursor to finish before replacing this provider schedule")
		} else if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, ticketIntakeFrom(saved, true), nil
	})
}

func (a *API) getTicketIntakeSchedule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	system := strings.TrimSpace(r.URL.Query().Get("system"))
	if system == "" {
		system = ticketintake.SystemServiceNow
	}
	if system != ticketintake.SystemServiceNow && system != ticketintake.SystemJira {
		a.writeError(w, errStatus(http.StatusBadRequest, "system must be servicenow or jira"))
		return
	}
	sched, found, err := a.store.GetTicketIntakeSchedule(r.Context(), tenantID, system)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, ticketIntakeFrom(sched, found))
}

func ticketIntakeFrom(s store.TicketIntakeSchedule, found bool) ticketIntakeResponse {
	out := ticketIntakeResponse{
		Configured: found, System: s.System, InstanceURL: s.InstanceURL, TokenRef: s.TokenRef,
		SNTable: s.SNTable, JiraProject: s.JiraProject, Query: s.Query,
		SubjectField: s.SubjectField, ProfileField: s.ProfileField,
		RequesterField: s.RequesterField, JustificationField: s.JustificationField,
		IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled,
		AllowPrivateEndpoint: s.AllowPrivateEndpoint, PrivateEgressCIDRs: s.PrivateEgressCIDRs,
		SweepID: s.CurrentSweepID, NextCursor: s.Cursor, ReadCount: s.ReadCount,
		ExpectedCount: s.ExpectedCount, PagesCompleted: s.PagesCompleted,
		CoverageComplete: s.CoverageComplete, EligibleCount: s.EligibleCount,
		SkippedCount: s.SkippedCount, LastError: s.LastError, Guidance: ticketIntakeGuidance,
	}
	if s.LastRunAt != nil {
		out.LastRunAt = s.LastRunAt.UTC().Format(time.RFC3339)
	}
	if s.SweepStartedAt != nil {
		out.SweepStartedAt = s.SweepStartedAt.UTC().Format(time.RFC3339)
	}
	if s.LastAttemptAt != nil {
		out.LastAttemptAt = s.LastAttemptAt.UTC().Format(time.RFC3339)
	}
	return out
}
