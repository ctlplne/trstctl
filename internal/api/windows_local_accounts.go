// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	googleuuid "github.com/google/uuid"
	"net/http"
	"strconv"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

type PAMWindowsLocalAccountScanList struct {
	Items      []store.WindowsLocalAccountScan `json:"items"`
	NextCursor string                          `json:"next_cursor,omitempty"`
}
type PAMWindowsLocalAccountService interface {
	RunPAMWindowsLocalAccountInventory(context.Context, string, string, string, string) (store.WindowsLocalAccountScan, error)
	GetPAMWindowsLocalAccountScan(context.Context, string, string, string) (store.WindowsLocalAccountScan, error)
	ListPAMWindowsLocalAccountScans(context.Context, string, string, string, int) (PAMWindowsLocalAccountScanList, error)
}

func (a *API) windowsLocalAccountService() (PAMWindowsLocalAccountService, error) {
	s, ok := a.pam.(PAMWindowsLocalAccountService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return s, nil
}
func windowsLocalAccountError(err error) error {
	if errors.Is(err, store.ErrWindowsLocalAccountScanNotFound) {
		return errStatus(http.StatusNotFound, "Windows host inventory not found")
	}
	return pamDiscoveryNotFound(err)
}
func (a *API) pamWindowsLocalAccountRoutes() []route {
	root := "/api/v1/access/discovery/windows-hosts/{agent_id}/local-administrators/runs"
	return []route{
		{method: "POST", path: root, opID: "runPAMWindowsLocalAccountInventory", summary: "Queue read-only local administrator inventory on one enrolled Windows host", handler: a.runPAMWindowsLocalAccountInventory, pathParams: []param{pathUUID("agent_id")}, resSchema: "PAMWindowsLocalAccountScan", successCode: "202", perm: authz.AccessTargetsWrite},
		{method: "GET", path: root, opID: "listPAMWindowsLocalAccountScans", summary: "Page retained local administrator scans for an enrolled host", handler: a.listPAMWindowsLocalAccountScans, pathParams: []param{pathUUID("agent_id")}, query: []param{{name: "after", typ: "string", desc: "last scan UUID from the previous page"}, {name: "limit", typ: "integer", desc: "1-100 scans, default 25"}}, resSchema: "PAMWindowsLocalAccountScanList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: root + "/{id}", opID: "getPAMWindowsLocalAccountScan", summary: "Read exact signed local administrator inventory and delivery state", handler: a.getPAMWindowsLocalAccountScan, pathParams: []param{pathUUID("agent_id"), pathUUID("id")}, resSchema: "PAMWindowsLocalAccountScan", successCode: "200", perm: authz.AccessRead},
	}
}

//trstctl:mutation
func (a *API) runPAMWindowsLocalAccountInventory(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, t string) (int, any, error) {
		s, err := a.windowsLocalAccountService()
		if err != nil {
			return 0, nil, err
		}
		actor, agentID := principalSubject(ctx), r.PathValue("agent_id")
		// The outer AN-5 recorder can roll back while the source append survives.
		// Keep the native run identity stable across that same authenticated request.
		runID := googleuuid.NewSHA1(googleuuid.NameSpaceURL, []byte("trstctl/windows-local-inventory/request/v1\x00"+t+"\x00"+actor+"\x00"+agentID+"\x00"+r.Header.Get("Idempotency-Key"))).String()
		v, err := s.RunPAMWindowsLocalAccountInventory(ctx, t, actor, agentID, runID)
		return http.StatusAccepted, v, windowsLocalAccountError(err)
	})
}
func (a *API) getPAMWindowsLocalAccountScan(w http.ResponseWriter, r *http.Request) {
	s, err := a.windowsLocalAccountService()
	if err != nil {
		a.writeServiceDependentError(w, err)
		return
	}
	tenant, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	v, err := s.GetPAMWindowsLocalAccountScan(r.Context(), tenant, r.PathValue("agent_id"), r.PathValue("id"))
	if err != nil {
		a.writeServiceDependentError(w, windowsLocalAccountError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, v)
}
func (a *API) listPAMWindowsLocalAccountScans(w http.ResponseWriter, r *http.Request) {
	s, err := a.windowsLocalAccountService()
	if err != nil {
		a.writeServiceDependentError(w, err)
		return
	}
	tenant, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 100 {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be 1-100"))
			return
		}
		limit = n
	}
	v, err := s.ListPAMWindowsLocalAccountScans(r.Context(), tenant, r.PathValue("agent_id"), r.URL.Query().Get("after"), limit)
	if err != nil {
		a.writeServiceDependentError(w, windowsLocalAccountError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, v)
}
func windowsLocalAccountSchemas() map[string]*Schema {
	integer := func() *Schema { return &Schema{Type: "integer"} }
	boolean := func() *Schema { return &Schema{Type: "boolean"} }
	array := func(v *Schema) *Schema { return &Schema{Type: "array", Items: v} }
	id := func() *Schema { return &Schema{Type: "string", Format: "uuid"} }
	stamp := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	return map[string]*Schema{
		"PAMWindowsLocalAccountIntent":    object(map[string]*Schema{"run_id": id(), "tenant_id": id(), "agent_id": id(), "binding_digest": str()}, "run_id", "tenant_id", "agent_id", "binding_digest"),
		"PAMWindowsSAMMachine":            object(map[string]*Schema{"name": str(), "sid": str(), "role": integer()}, "name", "sid", "role"),
		"PAMWindowsLocalAccount":          object(map[string]*Schema{"name": str(), "sid": str(), "enabled": boolean(), "locked": boolean(), "password_required": boolean()}, "name", "sid", "enabled", "locked", "password_required"),
		"PAMWindowsLocalAccountInventory": object(map[string]*Schema{"machine": ref("PAMWindowsSAMMachine"), "accounts": array(ref("PAMWindowsLocalAccount")), "external_members": integer(), "group_members": integer(), "deleted_members": integer()}, "machine", "accounts", "external_members", "group_members", "deleted_members"),
		"PAMWindowsLocalAccountReport":    object(map[string]*Schema{"run_id": id(), "binding_digest": str(), "observed_at": stamp(), "status": {Type: "string", Enum: []string{"complete", "unavailable"}}, "failure": str(), "inventory": ref("PAMWindowsLocalAccountInventory")}, "run_id", "binding_digest", "observed_at", "status"),
		"PAMWindowsLocalAccountScan":      object(map[string]*Schema{"id": id(), "intent": ref("PAMWindowsLocalAccountIntent"), "status": {Type: "string", Enum: []string{"queued", "complete", "failed", "retrying"}}, "delivery_status": str(), "queued_by": str(), "queued_at": stamp(), "queued_event_id": id(), "outbox_id": integer(), "report": ref("PAMWindowsLocalAccountReport"), "report_digest": str(), "failure": str(), "received_at": stamp(), "receipt_job_id": integer(), "attempt": integer(), "receipt_statement": str(), "receipt_signature_base64": str(), "signer_fingerprint": str(), "observed_event_id": id()}, "id", "intent", "status", "delivery_status", "queued_by", "queued_at", "queued_event_id"),
		"PAMWindowsLocalAccountScanList":  object(map[string]*Schema{"items": array(ref("PAMWindowsLocalAccountScan")), "next_cursor": str()}, "items"),
	}
}
