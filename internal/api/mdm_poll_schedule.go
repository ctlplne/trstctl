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
	// Execution picks the vantage: "" / "control_plane" reads from the brain;
	// "relay" dispatches an mdm.sync job a network relay claims — the shape
	// for an on-prem Jamf the control plane cannot reach.
	Execution string `json:"execution,omitempty"`
	// RenewalWindowDays overrides the offline-renewal check's standard window.
	RenewalWindowDays int `json:"renewal_window_days,omitempty"`
	// AllowPrivateEndpoint + PrivateEgressCIDRs gate a control-plane poll of a
	// private MDM. The caller needs egress:private, and the CIDRs bound which
	// ranges the poll may dial. Relay execution needs neither.
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
	"token_ref is a reference (env: or secret://), never the token itself; relay execution requires " +
	"a secret:// reference because the relay redeems it per attempt from the secret store. No " +
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
		if strings.TrimSpace(body.TokenRef) == "" {
			return 0, nil, errStatus(http.StatusBadRequest,
				"token_ref is required; it is a reference such as secret://mdm/graph-token, never the token itself")
		}
		if body.IntervalSeconds < minMDMPollInterval {
			return 0, nil, errStatus(http.StatusBadRequest,
				"interval_seconds must be at least 300; device check-in state changes on the order of hours")
		}
		execution := strings.TrimSpace(body.Execution)
		switch execution {
		case "", "control_plane", "relay":
		default:
			return 0, nil, errStatus(http.StatusBadRequest, "execution must be control_plane or relay")
		}
		if execution == "relay" && !strings.HasPrefix(strings.TrimSpace(body.TokenRef), "secret://") {
			// Same custody rule as the CMDB's relay mode, for the same reason.
			return 0, nil, errStatus(http.StatusBadRequest,
				"relay execution requires a secret:// token_ref: the relay redeems the token from the "+
					"secret store per attempt, and an env: reference lives in the control plane's "+
					"environment, which the relay does not share")
		}
		if body.RenewalWindowDays < 0 || body.RenewalWindowDays > 365 {
			return 0, nil, errStatus(http.StatusBadRequest, "renewal_window_days must be between 0 (use the standard) and 365")
		}
		if body.AllowPrivateEndpoint {
			if execution == "relay" {
				return 0, nil, errStatus(http.StatusBadRequest,
					"allow_private_endpoint is a control-plane egress grant; relay execution reads from "+
						"inside the segment and needs no hole through the firewall — configure one or the other")
			}
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
			if len(body.PrivateEgressCIDRs) == 0 {
				return 0, nil, errStatus(http.StatusBadRequest,
					"allow_private_endpoint requires private_egress_cidrs naming exactly which ranges the poll may dial")
			}
			if err := validatePrivateEgressCIDRs(body.PrivateEgressCIDRs); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
		}
		saved := store.MDMPollSchedule{
			TenantID: tenantID, MDM: which,
			BaseURL:         strings.TrimSpace(body.BaseURL),
			TokenRef:        strings.TrimSpace(body.TokenRef),
			Filter:          strings.TrimSpace(body.Filter),
			IntervalSeconds: body.IntervalSeconds, Enabled: body.Enabled,
			AllowPrivateEndpoint: body.AllowPrivateEndpoint,
			PrivateEgressCIDRs:   cleanAPIStringList(body.PrivateEgressCIDRs),
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
