// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
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
	Query   string `json:"query,omitempty"`
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
	LastError            string   `json:"last_error,omitempty"`
	Guidance             string   `json:"guidance"`
}

const ticketIntakeGuidance = "The intake reads the named ServiceNow table on the tenant's interval " +
	"and opens one issuance request per ticket — idempotently by ticket reference, so a denied " +
	"request does not reopen (the denial WAS the answer; a fresh ask needs a fresh ticket). The " +
	"field mapping is explicit: tickets missing the mapped subject or profile are skipped and " +
	"counted, never guessed at. Requests opened here carry origin=servicenow and the ticket " +
	"reference, and the existing lifecycle — approval with separation of duties, denial with a " +
	"reason, expiry — decides them. The read is a durable ticket.sync job executed by a network " +
	"relay with per-attempt token redemption; the control plane never dials ServiceNow. Jira intake is not built."

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
		if strings.TrimSpace(body.System) != "servicenow" {
			return 0, nil, errStatus(http.StatusBadRequest,
				"system must be servicenow; Jira intake is not built and pretending otherwise would "+
					"configure a poll that never runs")
		}
		if err := requireAbsoluteURL(body.InstanceURL, "instance_url"); err != nil {
			return 0, nil, err
		}
		if !strings.HasPrefix(strings.TrimSpace(body.TokenRef), "secret://") {
			return 0, nil, errStatus(http.StatusBadRequest,
				"token_ref must be a secret:// reference redeemed by the network relay per attempt")
		}
		table := strings.TrimSpace(body.SNTable)
		if !ticketIntakeTables[table] {
			return 0, nil, errStatus(http.StatusBadRequest,
				"sn_table must be one of incident, sc_req_item, sc_request, change_request — the "+
					"request-shaped tables; an unbounded table name would aim the intake token at "+
					"records that are not tickets")
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
		saved := store.TicketIntakeSchedule{
			TenantID: tenantID, System: "servicenow",
			InstanceURL: strings.TrimSpace(body.InstanceURL),
			TokenRef:    strings.TrimSpace(body.TokenRef),
			SNTable:     table, Query: strings.TrimSpace(body.Query),
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
			SNTable: saved.SNTable, Query: saved.Query,
			SubjectField: saved.SubjectField, ProfileField: saved.ProfileField,
			RequesterField: saved.RequesterField, JustificationField: saved.JustificationField,
			IntervalSeconds: saved.IntervalSeconds, Enabled: saved.Enabled,
			AllowPrivate: saved.AllowPrivateEndpoint, PrivateCIDRs: saved.PrivateEgressCIDRs,
		}); err != nil {
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
	sched, found, err := a.store.GetTicketIntakeSchedule(r.Context(), tenantID, "servicenow")
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, ticketIntakeFrom(sched, found))
}

func ticketIntakeFrom(s store.TicketIntakeSchedule, found bool) ticketIntakeResponse {
	out := ticketIntakeResponse{
		Configured: found, System: s.System, InstanceURL: s.InstanceURL, TokenRef: s.TokenRef,
		SNTable: s.SNTable, Query: s.Query,
		SubjectField: s.SubjectField, ProfileField: s.ProfileField,
		RequesterField: s.RequesterField, JustificationField: s.JustificationField,
		IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled,
		AllowPrivateEndpoint: s.AllowPrivateEndpoint, PrivateEgressCIDRs: s.PrivateEgressCIDRs,
		LastError: s.LastError, Guidance: ticketIntakeGuidance,
	}
	if s.LastRunAt != nil {
		out.LastRunAt = s.LastRunAt.UTC().Format(time.RFC3339)
	}
	return out
}
