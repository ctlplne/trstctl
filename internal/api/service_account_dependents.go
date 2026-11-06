// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

type PAMServiceDependentHostList struct {
	Items      []store.ServiceDependentHost `json:"items"`
	NextCursor string                       `json:"next_cursor,omitempty"`
}
type PAMServiceDependentDiscoveryService interface {
	SavePAMServiceDependentHost(context.Context, string, string, string, string, bool) (store.ServiceDependentHost, error)
	ListPAMServiceDependentHosts(context.Context, string, string, string, int) (PAMServiceDependentHostList, error)
	RunPAMServiceDependentInventory(context.Context, string, string, string, string) (store.ServiceDependentScan, error)
	GetPAMServiceDependentScan(context.Context, string, string) (store.ServiceDependentScan, error)
}

func (a *API) serviceDependentDiscovery() (PAMServiceDependentDiscoveryService, error) {
	service, ok := a.pam.(PAMServiceDependentDiscoveryService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return service, nil
}
func serviceDependentError(err error) error {
	if errors.Is(err, store.ErrServiceDependentHostNotFound) || errors.Is(err, store.ErrServiceDependentScanNotFound) {
		return errStatus(http.StatusNotFound, "service-account dependent inventory not found")
	}
	return pamDiscoveryNotFound(err)
}
func (a *API) pamServiceDependentRoutes() []route {
	root := "/api/v1/access/discovery/accounts/{account_id}/dependents"
	return []route{
		{method: "GET", path: root, opID: "listPAMServiceDependentHosts", summary: "List selected enrolled hosts for an AD account, with a cursor", handler: a.listPAMServiceDependentHosts, pathParams: []param{pathUUID("account_id")}, query: []param{{name: "after", typ: "string", desc: "the last agent UUID from the previous page"}, {name: "limit", typ: "integer", desc: "1-256 hosts, default 50"}}, resSchema: "PAMServiceDependentHostList", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: root + "/{agent_id}", opID: "savePAMServiceDependentHost", summary: "Bind or disable one enrolled host for read-only AD account dependent inventory", handler: a.savePAMServiceDependentHost, pathParams: []param{pathUUID("account_id"), pathUUID("agent_id")}, reqSchema: "PAMServiceDependentHostRequest", resSchema: "PAMServiceDependentHost", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "POST", path: root + "/{agent_id}/runs", opID: "runPAMServiceDependentInventory", summary: "Queue a read-only service, task and IIS account inventory on the exact enrolled host", handler: a.runPAMServiceDependentInventory, pathParams: []param{pathUUID("account_id"), pathUUID("agent_id")}, resSchema: "PAMServiceDependentScan", successCode: "202", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "GET", path: "/api/v1/access/discovery/dependent-runs/{id}", opID: "getPAMServiceDependentScan", summary: "Read signed native dependent metadata and explicit coverage for one host scan", handler: a.getPAMServiceDependentScan, pathParams: []param{pathUUID("id")}, resSchema: "PAMServiceDependentScan", successCode: "200", perm: authz.AccessRead},
	}
}
func (a *API) listPAMServiceDependentHosts(w http.ResponseWriter, r *http.Request) {
	service, err := a.serviceDependentDiscovery()
	if err != nil {
		a.writeServiceDependentError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 256 {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be 1-256"))
			return
		}
		limit = n
	}
	result, err := service.ListPAMServiceDependentHosts(r.Context(), tenantID, r.PathValue("account_id"), r.URL.Query().Get("after"), limit)
	if err != nil {
		a.writeServiceDependentError(w, serviceDependentError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}

//trstctl:mutation
func (a *API) savePAMServiceDependentHost(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		service, err := a.serviceDependentDiscovery()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if body.Enabled == nil {
			return 0, nil, errStatus(http.StatusBadRequest, "enabled is required")
		}
		result, err := service.SavePAMServiceDependentHost(ctx, tenantID, principalSubject(ctx), r.PathValue("account_id"), r.PathValue("agent_id"), *body.Enabled)
		return http.StatusOK, result, serviceDependentError(err)
	})
}

//trstctl:mutation
func (a *API) runPAMServiceDependentInventory(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		service, err := a.serviceDependentDiscovery()
		if err != nil {
			return 0, nil, err
		}
		result, err := service.RunPAMServiceDependentInventory(ctx, tenantID, principalSubject(ctx), r.PathValue("account_id"), r.PathValue("agent_id"))
		return http.StatusAccepted, result, serviceDependentError(err)
	})
}
func (a *API) getPAMServiceDependentScan(w http.ResponseWriter, r *http.Request) {
	service, err := a.serviceDependentDiscovery()
	if err != nil {
		a.writeServiceDependentError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	result, err := service.GetPAMServiceDependentScan(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeServiceDependentError(w, serviceDependentError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}

func (a *API) writeServiceDependentError(w http.ResponseWriter, err error) {
	mapped := serviceDependentError(err)
	if !a.writePAMError(w, mapped) {
		a.writeError(w, mapped)
	}
}
