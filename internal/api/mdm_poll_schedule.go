// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// The MDM poll schedule (I5): the operator's standing instruction that makes
// the correlation surface a live one instead of a table tests write.

type mdmPollScheduleBody struct {
	MDM             string `json:"mdm"`
	BaseURL         string `json:"base_url"`
	TokenRef        string `json:"token_ref"`
	RequiredAgentID string `json:"required_agent_id,omitempty"`
	// Filter is Intune's $filter or Jamf's section selector; it travels as an
	// encoded query parameter, never a path segment.
	Filter          string `json:"filter,omitempty"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
	// Execution is relay-only. Empty means the safe relay default.
	Execution string `json:"execution,omitempty"`
	// RenewalWindowDays overrides the offline-renewal check's standard window.
	RenewalWindowDays int `json:"renewal_window_days,omitempty"`
	// ClientCredentials (Intune only, A156) names the Entra app registration;
	// token_ref then holds its client secret, which the relay exchanges per
	// attempt for a Microsoft Graph token.
	ClientCredentials *mdm.ClientCredentials `json:"client_credentials,omitempty"`
	// Legacy control-plane egress fields remain only for clear rejection.
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

type mdmPollScheduleResponse struct {
	Configured           bool     `json:"configured"`
	MDM                  string   `json:"mdm,omitempty"`
	BaseURL              string   `json:"base_url,omitempty"`
	TokenRef             string   `json:"token_ref,omitempty"`
	RequiredAgentID      string   `json:"required_agent_id,omitempty"`
	Filter               string   `json:"filter,omitempty"`
	IntervalSeconds      int      `json:"interval_seconds,omitempty"`
	Enabled              bool     `json:"enabled"`
	Execution            string   `json:"execution,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
	RenewalWindowDays    int      `json:"renewal_window_days,omitempty"`
	// ClientCredentials is the Intune app registration (identifiers only).
	ClientCredentials *mdm.ClientCredentials `json:"client_credentials,omitempty"`
	LastRunAt         string                 `json:"last_run_at,omitempty"`
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
	"attempt and the control plane never dials Microsoft Graph or Jamf. An enabled schedule binds " +
	"one exact enrolled network relay, so another same-tenant relay cannot redeem its bearer. For " +
	"Intune, client_credentials (directory_tenant_id and client_id of an Entra app registration with " +
	"Graph application permissions) makes token_ref the app's client secret: the relay exchanges it " +
	"per attempt for a Microsoft Graph token that lives only in memory for that read. Otherwise the " +
	"reference must resolve to a bearer the MDM accepts, rotated by the operator's own pipeline."

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
		requiredAgentID := strings.TrimSpace(body.RequiredAgentID)
		if body.Enabled && requiredAgentID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "required_agent_id must name the exact enrolled network relay before enabling a schedule")
		}
		if requiredAgentID != "" {
			if _, err := googleuuid.Parse(requiredAgentID); err != nil {
				return 0, nil, errStatus(http.StatusBadRequest, "required_agent_id must be an enrolled agent UUID")
			}
			if body.Enabled {
				readiness, err := a.orch.DiscoveryNetworkRelayReadinessForJob(ctx, tenantID, requiredAgentID, "mdm.sync")
				if err != nil {
					return 0, nil, err
				}
				if !readiness.Ready {
					return 0, nil, errStatus(http.StatusConflict, readiness.BlockedReason)
				}
			} else {
				agent, err := a.store.GetAgent(ctx, tenantID, requiredAgentID)
				if err != nil {
					return 0, nil, err
				}
				if agent.Status == "offboarded" || !slices.Contains(agent.Roles, "network") {
					return 0, nil, errStatus(http.StatusConflict, "required_agent_id must name a non-offboarded network relay")
				}
			}
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
		var app *mdm.ClientCredentials
		if body.ClientCredentials != nil {
			if which != mdm.MDMIntune {
				return 0, nil, errStatus(http.StatusBadRequest, "client_credentials are only valid for an Intune schedule")
			}
			normalized := body.ClientCredentials.Normalize()
			if err := normalized.Validate(); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
			app = &normalized
		}
		saved := store.MDMPollSchedule{
			TenantID: tenantID, MDM: which,
			BaseURL:         strings.TrimSpace(body.BaseURL),
			TokenRef:        strings.TrimSpace(body.TokenRef),
			RequiredAgentID: requiredAgentID,
			Filter:          strings.TrimSpace(body.Filter),
			IntervalSeconds: body.IntervalSeconds, Enabled: body.Enabled,
			AllowPrivateEndpoint: false,
			PrivateEgressCIDRs:   nil,
			Execution:            execution, RenewalWindowDays: body.RenewalWindowDays,
		}
		var event *projections.MDMPollClientCredentials
		if app != nil {
			saved.EntraAuthority, saved.EntraDirectoryTenantID, saved.EntraClientID = app.Authority, app.DirectoryTenantID, app.ClientID
			event = &projections.MDMPollClientCredentials{Authority: app.Authority, DirectoryTenantID: app.DirectoryTenantID, ClientID: app.ClientID}
		}
		if err := a.orch.ConfigureMDMPollSchedule(ctx, tenantID, projections.MDMPollConfigured{
			MDM: saved.MDM, BaseURL: saved.BaseURL, TokenRef: saved.TokenRef, Filter: saved.Filter,
			RequiredAgentID: saved.RequiredAgentID,
			IntervalSeconds: saved.IntervalSeconds, Enabled: saved.Enabled,
			AllowPrivate: saved.AllowPrivateEndpoint, PrivateCIDRs: saved.PrivateEgressCIDRs,
			Execution: saved.Execution, RenewalWindowDays: saved.RenewalWindowDays,
			ClientCredentials: event,
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
		RequiredAgentID: s.RequiredAgentID,
		IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled, Execution: s.Execution,
		AllowPrivateEndpoint: s.AllowPrivateEndpoint, PrivateEgressCIDRs: s.PrivateEgressCIDRs,
		RenewalWindowDays: s.RenewalWindowDays, LastError: s.LastError, Guidance: mdmPollGuidance,
	}
	if s.EntraClientID != "" {
		out.ClientCredentials = &mdm.ClientCredentials{Authority: s.EntraAuthority, DirectoryTenantID: s.EntraDirectoryTenantID, ClientID: s.EntraClientID}
	}
	if s.LastRunAt != nil {
		out.LastRunAt = s.LastRunAt.UTC().Format(time.RFC3339)
	}
	return out
}
