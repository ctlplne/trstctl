// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Closing an incident (P13). The closure is recorded once; naming the
// approved ServiceNow binding also resolves the ServiceNow incident the
// response dispatch opened for it (found by the incident's correlation ID),
// and the closure reads back that resolution's state.

type incidentCloseRequest struct {
	Resolution string `json:"resolution"`
	ServiceNow *struct {
		InstanceURL          string `json:"instance_url"`
		TokenRef             string `json:"token_ref"`
		AllowPrivateEndpoint bool   `json:"allow_private_endpoint"`
	} `json:"servicenow,omitempty"`
}

type incidentClosureView struct {
	IncidentID string    `json:"incident_id"`
	Resolution string    `json:"resolution"`
	ClosedBy   string    `json:"closed_by"`
	ClosedAt   time.Time `json:"closed_at"`
	// ServiceNow is "" with no binding named, else queued, resolved or failed.
	ServiceNow      string `json:"servicenow,omitempty"`
	ServiceNowError string `json:"servicenow_error,omitempty"`
}

func incidentClosureResponse(c store.IncidentClosure) incidentClosureView {
	view := incidentClosureView{IncidentID: c.IncidentID, Resolution: c.Resolution, ClosedBy: c.ClosedBy, ClosedAt: c.ClosedAt}
	if c.ServiceNow {
		switch c.JobStatus {
		case "done", "delivered", "completed", "succeeded":
			view.ServiceNow = "resolved"
		case "failed", "dead_letter", "cancelled":
			view.ServiceNow, view.ServiceNowError = "failed", c.JobError
		default:
			view.ServiceNow = "queued"
		}
	}
	return view
}

func (a *API) incidentCloseRoutes() []route {
	idPath := []param{pathString("id", "incident execution id")}
	return []route{
		{method: "POST", path: "/api/v1/incidents/executions/{id}/close", opID: "closeIncidentExecution", summary: "Close an incident; naming the approved ServiceNow binding also resolves the ServiceNow incident its response dispatch opened", handler: a.closeIncidentExecution, pathParams: idPath, reqSchema: "IncidentCloseRequest", resSchema: "IncidentClosure", successCode: "200", mutation: true, perm: authz.IncidentsWrite},
		{method: "GET", path: "/api/v1/incidents/executions/{id}/closure", opID: "getIncidentClosure", summary: "Read an incident's closure and the state of its ServiceNow resolution", handler: a.getIncidentClosure, pathParams: idPath, resSchema: "IncidentClosure", successCode: "200", perm: authz.IncidentsRead},
	}
}

//trstctl:mutation
func (a *API) closeIncidentExecution(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		id := strings.TrimSpace(r.PathValue("id"))
		var req incidentCloseRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Resolution = strings.TrimSpace(req.Resolution)
		if req.Resolution == "" || len(req.Resolution) > 500 {
			return 0, nil, errStatus(http.StatusBadRequest, "resolution is required (at most 500 characters)")
		}
		if _, err := a.store.GetIncidentExecution(ctx, tenantID, id); err != nil {
			if store.IsNotFound(err) {
				return 0, nil, errStatus(http.StatusNotFound, "incident not found")
			}
			return 0, nil, err
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		var closeJob *orchestrator.ServiceNowCloseRequest
		if req.ServiceNow != nil {
			binding, err := a.approvedServiceNowBinding(serviceNowTicketRequest{InstanceURL: req.ServiceNow.InstanceURL,
				TokenRef: req.ServiceNow.TokenRef, AllowPrivateEndpoint: req.ServiceNow.AllowPrivateEndpoint}, false)
			if err != nil {
				return 0, nil, err
			}
			if binding.AllowPrivateEndpoint {
				if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
					return 0, nil, err
				}
			}
			closeJob = &orchestrator.ServiceNowCloseRequest{IncidentID: id, InstanceURL: binding.InstanceURL, Table: "incident",
				TokenRef: binding.TokenRef, CorrelationID: orchestrator.IncidentCorrelationID(id),
				CloseNotes:           "Closed in trstctl (incident " + id + "): " + req.Resolution,
				AllowPrivateEndpoint: binding.AllowPrivateEndpoint, PrivateEgressCIDRs: binding.PrivateEgressCIDRs}
		}
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "incident closure is not configured")
		}
		err = a.orch.CloseIncident(ctx, tenantID, projections.IncidentClosed{IncidentID: id, Resolution: req.Resolution,
			ClosedBy: subject}, closeJob)
		if errors.Is(err, orchestrator.ErrIncidentAlreadyClosed) {
			return 0, nil, errStatus(http.StatusConflict, "this incident is already closed")
		}
		if err != nil {
			return 0, nil, err
		}
		closure, _, err := a.store.GetIncidentClosure(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, incidentClosureResponse(closure), nil
	})
}

func (a *API) getIncidentClosure(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	closure, found, err := a.store.GetIncidentClosure(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		a.writeError(w, err)
		return
	}
	if !found {
		a.writeError(w, errStatus(http.StatusNotFound, "this incident is not closed"))
		return
	}
	a.writeJSON(w, http.StatusOK, incidentClosureResponse(closure))
}

func incidentCloseSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	return map[string]*Schema{
		"IncidentCloseRequest": {Type: "object", Required: []string{"resolution"}, Properties: map[string]*Schema{
			"resolution": str(),
			"servicenow": {Type: "object", Required: []string{"instance_url", "token_ref"}, Properties: map[string]*Schema{
				"instance_url": str(), "token_ref": str(), "allow_private_endpoint": {Type: "boolean"}}},
		}},
		"IncidentClosure": {Type: "object", Required: []string{"incident_id", "resolution", "closed_by", "closed_at"}, Properties: map[string]*Schema{
			"incident_id": str(), "resolution": str(), "closed_by": str(), "closed_at": {Type: "string", Format: "date-time"},
			"servicenow": {Type: "string", Enum: []string{"queued", "resolved", "failed"}}, "servicenow_error": str(),
		}},
	}
}
