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

// The served half of scheduled CMDB reconciliation (I2).
//
// Three operations, and deliberately no fourth: there is no endpoint that
// writes to the CMDB. "No CMDB write unless explicitly configured" is held here
// as an absence — the read path builds GET requests against a fixed cmdb_ci
// path, and the ticket writer's table allow-list rejects cmdb_ci — rather than
// as a flag somebody could flip.

type cmdbScheduleBody struct {
	InstanceURL string `json:"instance_url"`
	TokenRef    string `json:"token_ref"`
	CIQuery     string `json:"ci_query"`
	// AllowPrivateEndpoint mirrors the ticket writer's field exactly, and is
	// checked against the same operator binding and the same egress:private
	// permission. A second rule for the same risk is a second rule to get wrong.
	AllowPrivateEndpoint bool `json:"allow_private_endpoint"`
	// IntervalSeconds is how often to re-read. A CMDB is not a real-time
	// system and a tight poll buys nothing but rate limiting.
	IntervalSeconds int  `json:"interval_seconds"`
	Enabled         bool `json:"enabled"`
	// Execution picks the sync vantage (I2): "" / "control_plane" runs the
	// read from the control plane under the private-egress rules above;
	// "relay" dispatches a cmdb.sync job that a network relay inside the
	// segment claims — the model for a ServiceNow instance the control plane
	// cannot reach at all.
	Execution string `json:"execution,omitempty"`
}

type cmdbScheduleResponse struct {
	// Configured distinguishes "never set up" from "set up and paused". They
	// are different operator states and a bare enabled flag merges them.
	Configured           bool   `json:"configured"`
	InstanceURL          string `json:"instance_url"`
	TokenRef             string `json:"token_ref"`
	CIQuery              string `json:"ci_query"`
	AllowPrivateEndpoint bool   `json:"allow_private_endpoint"`
	IntervalSeconds      int    `json:"interval_seconds"`
	Enabled              bool   `json:"enabled"`
	Execution            string `json:"execution,omitempty"`
	LastRunAt            string `json:"last_run_at,omitempty"`
	// LastError is served, not just logged. A sync that has been failing for a
	// week otherwise looks identical to one that found nothing to do.
	LastError string `json:"last_error,omitempty"`
	Guidance  string `json:"guidance"`
}

const cmdbScheduleGuidance = "This reads cmdb_ci and never writes to it. A CMDB may fill in " +
	"ownership nobody recorded and may not overwrite ownership a human attested — that becomes a " +
	"conflict for someone to resolve. A CI naming an owner this estate has never heard of does NOT " +
	"create one: a CMDB's assignment group is not evidence that a trstctl owner should exist, and " +
	"auto-creating would build a parallel estate out of the CMDB's typos."

// minCMDBInterval floors the poll. Below this an operator is generating rate
// limiting, not freshness — a CMDB's ownership columns change on the order of
// days.
const minCMDBInterval = 300

func (a *API) putCMDBSchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body cmdbScheduleBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := requireAbsoluteURL(body.InstanceURL, "instance_url"); err != nil {
			return 0, nil, err
		}
		if strings.TrimSpace(body.TokenRef) == "" {
			return 0, nil, errStatus(http.StatusBadRequest,
				"token_ref is required; it is a reference such as env:TRSTCTL_SERVICENOW_TOKEN, never the token itself")
		}
		if body.IntervalSeconds < minCMDBInterval {
			return 0, nil, errStatus(http.StatusBadRequest,
				"interval_seconds must be at least 300; a CMDB's ownership columns change on the order of days, and a tighter poll buys rate limiting rather than freshness")
		}
		execution := strings.TrimSpace(body.Execution)
		switch execution {
		case "", "control_plane", "relay":
		default:
			return 0, nil, errStatus(http.StatusBadRequest,
				"execution must be control_plane or relay")
		}
		if execution == "relay" && !strings.HasPrefix(strings.TrimSpace(body.TokenRef), "secret://") {
			// The relay redeems the token through the job-credential path, which
			// resolves secret:// references. An env: reference names a variable
			// in the CONTROL PLANE's environment — a process the relay is not —
			// so accepting it would configure a sync that fails on its first
			// claim with an error three hops from the mistake.
			return 0, nil, errStatus(http.StatusBadRequest,
				"relay execution requires a secret:// token_ref: the relay redeems the token from the "+
					"secret store per attempt, and an env: reference lives in the control plane's "+
					"environment, which the relay does not share")
		}
		// The instance must already be an operator-approved ServiceNow
		// destination. Without this a tenant could aim the control plane's
		// credentials at any host it liked and call it a CMDB.
		if body.AllowPrivateEndpoint {
			// Same gate as the ticket path: reaching inside a private network is
			// an operator grant plus a caller permission, never one alone.
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
		}
		if _, err := a.approvedServiceNowBinding(serviceNowTicketRequest{
			InstanceURL:          body.InstanceURL,
			TokenRef:             body.TokenRef,
			AllowPrivateEndpoint: body.AllowPrivateEndpoint,
		}); err != nil {
			return 0, nil, err
		}
		saved := store.CMDBReconcileSchedule{
			InstanceURL:          strings.TrimSpace(body.InstanceURL),
			TokenRef:             strings.TrimSpace(body.TokenRef),
			CIQuery:              strings.TrimSpace(body.CIQuery),
			AllowPrivateEndpoint: body.AllowPrivateEndpoint,
			IntervalSeconds:      body.IntervalSeconds,
			Enabled:              body.Enabled,
			Execution:            execution,
		}
		if err := a.orch.ConfigureCMDBSchedule(ctx, tenantID, projections.CMDBScheduleConfigured{
			InstanceURL: saved.InstanceURL, TokenRef: saved.TokenRef, CIQuery: saved.CIQuery,
			AllowPrivateEndpoint: saved.AllowPrivateEndpoint,
			IntervalSeconds:      saved.IntervalSeconds, Enabled: saved.Enabled,
			Execution: saved.Execution,
		}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, cmdbScheduleFrom(saved, true), nil
	})
}

func (a *API) getCMDBSchedule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		// a.tenant does NOT write a response. Returning silently here would send
		// an empty 200 to an unauthenticated caller — a read that looks like it
		// succeeded and found no schedule.
		a.writeProblem(w, problemUnauthorized())
		return
	}
	sched, found, err := a.store.GetCMDBReconcileSchedule(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, cmdbScheduleFrom(sched, found))
}

func cmdbScheduleFrom(s store.CMDBReconcileSchedule, found bool) cmdbScheduleResponse {
	out := cmdbScheduleResponse{
		Configured:           found,
		InstanceURL:          s.InstanceURL,
		TokenRef:             s.TokenRef,
		CIQuery:              s.CIQuery,
		AllowPrivateEndpoint: s.AllowPrivateEndpoint,
		IntervalSeconds:      s.IntervalSeconds,
		Enabled:              s.Enabled,
		Execution:            s.Execution,
		LastError:            s.LastError,
		Guidance:             cmdbScheduleGuidance,
	}
	if s.LastRunAt != nil {
		out.LastRunAt = s.LastRunAt.UTC().Format(time.RFC3339)
	}
	return out
}
