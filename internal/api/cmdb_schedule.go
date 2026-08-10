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
// The control plane configures and ingests; a network relay performs the read.
// There is no CMDB writer and no control-plane HTTP fallback.

type cmdbScheduleBody struct {
	InstanceURL string `json:"instance_url"`
	TokenRef    string `json:"token_ref"`
	CIQuery     string `json:"ci_query"`
	// Kept in the wire shape for an actionable migration error. Relay execution
	// needs no control-plane private-egress grant and true is refused.
	AllowPrivateEndpoint bool `json:"allow_private_endpoint"`
	// IntervalSeconds is how often to re-read. A CMDB is not a real-time
	// system and a tight poll buys nothing but rate limiting.
	IntervalSeconds int  `json:"interval_seconds"`
	Enabled         bool `json:"enabled"`
	// Execution is relay-only. Empty is accepted as the safe default.
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
	"auto-creating would build a parallel estate out of the CMDB's typos. The read always runs as " +
	"a durable network-relay job with a per-attempt secret:// token redemption; the control plane " +
	"does not dial the CMDB."

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
		if !strings.HasPrefix(strings.TrimSpace(body.TokenRef), "secret://") {
			return 0, nil, errStatus(http.StatusBadRequest,
				"token_ref must be a secret:// reference; the network relay redeems it per attempt and the control plane never holds the token")
		}
		if body.IntervalSeconds < minCMDBInterval {
			return 0, nil, errStatus(http.StatusBadRequest,
				"interval_seconds must be at least 300; a CMDB's ownership columns change on the order of days, and a tighter poll buys rate limiting rather than freshness")
		}
		execution := strings.TrimSpace(body.Execution)
		if execution != "" && execution != "relay" {
			return 0, nil, errStatus(http.StatusBadRequest,
				"execution must be relay; control-plane external polling was removed because it bypasses the durable outbox and returns private-estate credentials to the brain")
		}
		execution = "relay"
		if body.AllowPrivateEndpoint {
			return 0, nil, errStatus(http.StatusBadRequest,
				"allow_private_endpoint is a control-plane egress grant and is not valid for relay-only CMDB reads; enroll a network relay in the segment instead")
		}
		// The instance must already be an operator-approved ServiceNow
		// destination. Without this a tenant could aim the control plane's
		// credentials at any host it liked and call it a CMDB.
		if _, err := a.approvedServiceNowBinding(serviceNowTicketRequest{
			InstanceURL:          body.InstanceURL,
			TokenRef:             body.TokenRef,
			AllowPrivateEndpoint: false,
		}); err != nil {
			return 0, nil, err
		}
		saved := store.CMDBReconcileSchedule{
			InstanceURL:          strings.TrimSpace(body.InstanceURL),
			TokenRef:             strings.TrimSpace(body.TokenRef),
			CIQuery:              strings.TrimSpace(body.CIQuery),
			AllowPrivateEndpoint: false,
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
