// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// The MDM poll schedule (I5): the operator's standing instruction that makes
// the correlation surface a live one instead of a table tests write.

type mdmPollScheduleBody struct {
	MDM      string `json:"mdm"`
	BaseURL  string `json:"base_url"`
	TokenRef string `json:"token_ref"`
	// Filter is Intune's $filter or Jamf's section selector; it travels as an
	// encoded query parameter, never a path segment.
	Filter          string `json:"filter,omitempty"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
	// Execution is relay-only. Empty means the safe relay default.
	Execution string `json:"execution,omitempty"`
	// RenewalWindowDays overrides the offline-renewal check's standard window.
	RenewalWindowDays int `json:"renewal_window_days,omitempty"`
	// Legacy control-plane egress fields remain only for clear rejection.
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

type mdmPollScheduleResponse struct {
	Configured           bool     `json:"configured"`
	MDM                  string   `json:"mdm,omitempty"`
	BaseURL              string   `json:"base_url,omitempty"`
	TokenRef             string   `json:"token_ref,omitempty"`
	Filter               string   `json:"filter,omitempty"`
	IntervalSeconds      int      `json:"interval_seconds,omitempty"`
	Enabled              bool     `json:"enabled"`
	Execution            string   `json:"execution,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
	RenewalWindowDays    int      `json:"renewal_window_days,omitempty"`
	LastRunAt            string   `json:"last_run_at,omitempty"`
	// LastError is served, not just logged: a poll failing for a week
	// otherwise looks identical to one with nothing to do.
	LastError string `json:"last_error,omitempty"`
	Guidance  string `json:"guidance"`
}

type mdmPollScheduleList struct {
	Items    []mdmPollScheduleResponse `json:"items"`
	Guidance string                    `json:"guidance"`
}

const mdmPollGuidance = "The poll re-reads the MDM on the tenant's own interval and correlates " +
	"devices to SCEP-enrolled identities by EXACT serial match. It is read-only by construction. " +
	"token_ref is a secret:// reference, never the token itself; a network relay redeems it per " +
	"attempt and the control plane never dials Microsoft Graph or Jamf. No " +
	"built-in OAuth exchange is performed: the reference must resolve to a bearer the MDM accepts, " +
	"rotated by the operator's own pipeline."

// minMDMPollInterval floors the poll, same reasoning as the CMDB's: device
// check-in state changes on the order of hours, and a tight poll buys rate
// limiting rather than freshness.
const minMDMPollInterval = 300

func (a *API) putMDMPollSchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body mdmPollScheduleBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		which := strings.TrimSpace(body.MDM)
		if which != mdm.MDMIntune && which != mdm.MDMJamf {
			return 0, nil, errStatus(http.StatusBadRequest, "mdm must be intune or jamf")
		}
		if err := requireAbsoluteURL(body.BaseURL, "base_url"); err != nil {
			return 0, nil, err
		}
		if !strings.HasPrefix(strings.TrimSpace(body.TokenRef), "secret://") {
			return 0, nil, errStatus(http.StatusBadRequest,
				"token_ref must be a secret:// reference redeemed by the network relay per attempt")
		}
		if body.IntervalSeconds < minMDMPollInterval {
			return 0, nil, errStatus(http.StatusBadRequest,
				"interval_seconds must be at least 300; device check-in state changes on the order of hours")
		}
		execution := strings.TrimSpace(body.Execution)
		if execution != "" && execution != "relay" {
			return 0, nil, errStatus(http.StatusBadRequest, "execution must be relay; control-plane external polling was removed")
		}
		execution = "relay"
		if body.RenewalWindowDays < 0 || body.RenewalWindowDays > 365 {
			return 0, nil, errStatus(http.StatusBadRequest, "renewal_window_days must be between 0 (use the standard) and 365")
		}
		if body.AllowPrivateEndpoint {
			return 0, nil, errStatus(http.StatusBadRequest,
				"allow_private_endpoint is a control-plane egress grant and is not valid for relay-only MDM reads")
		}
		saved := store.MDMPollSchedule{
			TenantID: tenantID, MDM: which,
			BaseURL:         strings.TrimSpace(body.BaseURL),
			TokenRef:        strings.TrimSpace(body.TokenRef),
			Filter:          strings.TrimSpace(body.Filter),
			IntervalSeconds: body.IntervalSeconds, Enabled: body.Enabled,
			AllowPrivateEndpoint: false,
			PrivateEgressCIDRs:   nil,
			Execution:            execution, RenewalWindowDays: body.RenewalWindowDays,
		}
		if err := a.orch.ConfigureMDMPollSchedule(ctx, tenantID, projections.MDMPollConfigured{
			MDM: saved.MDM, BaseURL: saved.BaseURL, TokenRef: saved.TokenRef, Filter: saved.Filter,
			IntervalSeconds: saved.IntervalSeconds, Enabled: saved.Enabled,
			AllowPrivate: saved.AllowPrivateEndpoint, PrivateCIDRs: saved.PrivateEgressCIDRs,
			Execution: saved.Execution, RenewalWindowDays: saved.RenewalWindowDays,
		}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, mdmPollScheduleFrom(saved, true), nil
	})
}

func (a *API) listMDMPollSchedules(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	schedules, err := a.store.ListMDMPollSchedules(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := mdmPollScheduleList{Items: []mdmPollScheduleResponse{}, Guidance: mdmPollGuidance}
	for _, sch := range schedules {
		out.Items = append(out.Items, mdmPollScheduleFrom(sch, true))
	}
	a.writeJSON(w, http.StatusOK, out)
}

func mdmPollScheduleFrom(s store.MDMPollSchedule, found bool) mdmPollScheduleResponse {
	out := mdmPollScheduleResponse{
		Configured: found, MDM: s.MDM, BaseURL: s.BaseURL, TokenRef: s.TokenRef, Filter: s.Filter,
		IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled, Execution: s.Execution,
		AllowPrivateEndpoint: s.AllowPrivateEndpoint, PrivateEgressCIDRs: s.PrivateEgressCIDRs,
		RenewalWindowDays: s.RenewalWindowDays, LastError: s.LastError, Guidance: mdmPollGuidance,
	}
	if s.LastRunAt != nil {
		out.LastRunAt = s.LastRunAt.UTC().Format(time.RFC3339)
	}
	return out
}
