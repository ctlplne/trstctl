// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// A260: privileged account discovery. A source is one of the tenant's
// dynamic-secret providers whose administrator connection reads its target's
// accounts; a run scans it read-only and stages the privileged accounts it
// finds, with what changed since the source's previous scan. Discovery grants
// nothing.

// PAMDiscoverySource is a provider whose target discovery scans, on demand or
// every interval_seconds (0 = on demand only).
type PAMDiscoverySource struct {
	ProviderID      string           `json:"provider_id"`
	ProviderType    string           `json:"provider_type"`
	IntervalSeconds int              `json:"interval_seconds"`
	SavedBy         string           `json:"saved_by,omitempty"`
	SavedAt         time.Time        `json:"saved_at"`
	LastRun         *PAMDiscoveryRun `json:"last_run,omitempty"`
}

// PAMDiscoveryRun is one scan of a source: what it found and how that
// differs from the source's previous complete scan, or the class of why it
// could not scan (failure: unreachable, rejected, expired, locked, error,
// not_supported, too_many).
type PAMDiscoveryRun struct {
	ID          string               `json:"id"`
	ProviderID  string               `json:"provider_id"`
	Status      string               `json:"status"`
	Failure     string               `json:"failure,omitempty"`
	RequestedBy string               `json:"requested_by"`
	StartedAt   time.Time            `json:"started_at"`
	FinishedAt  time.Time            `json:"finished_at"`
	Accounts    int                  `json:"accounts"`
	Added       int                  `json:"added"`
	Removed     int                  `json:"removed"`
	Changed     int                  `json:"changed"`
	Changes     []PAMDiscoveryChange `json:"changes,omitempty"`
}

// PAMDiscoveryChange is one account a run found added, removed or changed.
type PAMDiscoveryChange struct {
	Change  string                   `json:"change"`
	Account PAMDiscoveredAccountInfo `json:"account"`
}

// PAMDiscoveredAccountInfo is a privileged account as a scan saw it: its
// name, kind (local_user, database_role, database_user, sql_login), the
// privileges that make it privileged and whether it is disabled. Details
// hold bounded facts such as a shell, a uid or authorized keys' fingerprints;
// never a credential.
type PAMDiscoveredAccountInfo struct {
	Key        string            `json:"key"`
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Privileges []string          `json:"privileges"`
	Disabled   bool              `json:"disabled"`
	Details    map[string]string `json:"details,omitempty"`
}

// PAMDiscoveredAccount is a privileged account discovery has staged.
type PAMDiscoveredAccount struct {
	ID         string `json:"id"`
	ProviderID string `json:"provider_id"`
	PAMDiscoveredAccountInfo
	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	RemovedAt   *time.Time `json:"removed_at,omitempty"`
	Status      string     `json:"status"`
}

// PAMDiscoveryImportRequest imports staged accounts into a folder (part 2):
// requested first for independent review, then applied with the approval's
// exact request ID and intent digest. An account that changed since the
// review is refused, and a new request is needed.
type PAMDiscoveryImportRequest struct {
	RequestID         string   `json:"request_id"`
	AccountIDs        []string `json:"account_ids"`
	Folder            string   `json:"folder"`
	TemplateID        string   `json:"template_id,omitempty"`
	Reason            string   `json:"reason"`
	ApprovalRequestID string   `json:"approval_request_id,omitempty"`
	IntentDigest      string   `json:"intent_digest,omitempty"`
}

// PAMDiscoveryImportReview is an import's review: the approval request
// reviewers decide.
type PAMDiscoveryImportReview struct {
	RequestID         string    `json:"request_id"`
	ApprovalRequestID string    `json:"approval_request_id"`
	IntentDigest      string    `json:"intent_digest"`
	Status            string    `json:"status"`
	ApprovalCount     int       `json:"approval_count"`
	RequiredApprovals int       `json:"required_approvals"`
	ExpiresAt         time.Time `json:"expires_at"`
	Accounts          int       `json:"accounts"`
}

// PAMImportedAccount is an account imported into a folder. Importing grants
// nothing: no target, role, session or credential.
type PAMImportedAccount struct {
	ID                string    `json:"id"`
	ProviderID        string    `json:"provider_id"`
	Key               string    `json:"key"`
	Name              string    `json:"name"`
	Kind              string    `json:"kind"`
	Privileges        []string  `json:"privileges"`
	Folder            string    `json:"folder"`
	TemplateID        string    `json:"template_id,omitempty"`
	Reason            string    `json:"reason"`
	RequestID         string    `json:"request_id"`
	ApprovalRequestID string    `json:"approval_request_id"`
	ImportedBy        string    `json:"imported_by"`
	ImportedAt        time.Time `json:"imported_at"`
}

// PAMDiscoveryService is privileged account discovery; the served broker
// implements it.
type PAMDiscoveryService interface {
	SavePAMDiscoverySource(ctx context.Context, tenantID, actor, providerID string, intervalSeconds int) (PAMDiscoverySource, error)
	ListPAMDiscoverySources(ctx context.Context, tenantID string) ([]PAMDiscoverySource, error)
	DeletePAMDiscoverySource(ctx context.Context, tenantID, actor, providerID string) error
	RunPAMDiscovery(ctx context.Context, tenantID, actor, providerID string) (PAMDiscoveryRun, error)
	ListPAMDiscoveryRuns(ctx context.Context, tenantID, providerID string, limit int) ([]PAMDiscoveryRun, error)
	GetPAMDiscoveryRun(ctx context.Context, tenantID, id string) (PAMDiscoveryRun, error)
	ListPAMDiscoveredAccounts(ctx context.Context, tenantID, providerID, status string, includeRemoved bool) ([]PAMDiscoveredAccount, error)
	RequestPAMDiscoveryImport(ctx context.Context, tenantID, requester string, req PAMDiscoveryImportRequest) (PAMDiscoveryImportReview, error)
	ApplyPAMDiscoveryImport(ctx context.Context, tenantID, requester string, req PAMDiscoveryImportRequest) ([]PAMImportedAccount, error)
	DismissPAMDiscoveredAccount(ctx context.Context, tenantID, actor, id, reason string) (PAMDiscoveredAccount, error)
	ListPAMImportedAccounts(ctx context.Context, tenantID, folder, providerID string) ([]PAMImportedAccount, error)
}

func (a *API) pamDiscoveryRoutes() []route {
	provider := []param{pathString("provider_id", "the dynamic-secret provider's ID")}
	routes := []route{
		{method: "GET", path: "/api/v1/access/discovery/sources", opID: "listPAMDiscoverySources", summary: "List the providers whose targets privileged account discovery scans, with each one's last run", handler: a.listPAMDiscoverySources, resSchema: "PAMDiscoverySourceList", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/discovery/sources/{provider_id}", opID: "savePAMDiscoverySource", summary: "Scan a provider's target for privileged accounts on demand, or every interval_seconds (at least an hour); read-only", handler: a.savePAMDiscoverySource, pathParams: provider, reqSchema: "PAMDiscoverySourceRequest", resSchema: "PAMDiscoverySource", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "DELETE", path: "/api/v1/access/discovery/sources/{provider_id}", opID: "deletePAMDiscoverySource", summary: "Stop scanning a provider's target; its runs and staged accounts stay", handler: a.deletePAMDiscoverySource, pathParams: provider, resSchema: "PAMDiscoverySourceDeleted", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "POST", path: "/api/v1/access/discovery/sources/{provider_id}/runs", opID: "runPAMDiscovery", summary: "Scan a source's target now, read-only, and stage the privileged accounts it finds", handler: a.runPAMDiscovery, pathParams: provider, resSchema: "PAMDiscoveryRun", successCode: "201", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "GET", path: "/api/v1/access/discovery/runs", opID: "listPAMDiscoveryRuns", summary: "List discovery runs, newest first", handler: a.listPAMDiscoveryRuns, query: []param{{name: "provider_id", typ: "string", desc: "only this source's runs"}, {name: "limit", typ: "integer", desc: "at most this many (default 50, at most 500)"}}, resSchema: "PAMDiscoveryRunList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/discovery/runs/{id}", opID: "getPAMDiscoveryRun", summary: "Get a discovery run with the accounts it found added, removed or changed", handler: a.getPAMDiscoveryRun, pathParams: []param{pathUUID("id")}, resSchema: "PAMDiscoveryRun", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/discovery/imports", opID: "requestPAMDiscoveryImport", summary: "Request independent review of importing staged accounts into a folder; importing grants nothing", handler: a.requestPAMDiscoveryImport, reqSchema: "PAMDiscoveryImportRequest", resSchema: "PAMDiscoveryImportReview", successCode: "202", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "POST", path: "/api/v1/access/discovery/imports/{request_id}/apply", opID: "applyPAMDiscoveryImport", summary: "Apply an approved import with the approval's exact request ID and intent digest; an account changed since the review is refused", handler: a.applyPAMDiscoveryImport, pathParams: []param{pathUUID("request_id")}, reqSchema: "PAMDiscoveryImportRequest", resSchema: "PAMImportedAccountList", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "POST", path: "/api/v1/access/discovery/accounts/{id}/dismiss", opID: "dismissPAMDiscoveredAccount", summary: "Set a staged account aside with the reason; a scan that finds it changed stages it again", handler: a.dismissPAMDiscoveredAccount, pathParams: []param{pathUUID("id")}, reqSchema: "PAMDiscoveryDismissRequest", resSchema: "PAMDiscoveredAccount", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "GET", path: "/api/v1/access/accounts", opID: "listPAMImportedAccounts", summary: "List the privileged accounts imported into folders", handler: a.listPAMImportedAccounts, query: []param{{name: "folder", typ: "string", desc: "only this folder's accounts"}, {name: "provider_id", typ: "string", desc: "only this source's accounts"}}, resSchema: "PAMImportedAccountList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/discovery/accounts", opID: "listPAMDiscoveredAccounts", summary: "List the privileged accounts discovery has staged", handler: a.listPAMDiscoveredAccounts, query: []param{{name: "provider_id", typ: "string", desc: "only this source's accounts"}, {name: "status", typ: "string", desc: "staged, imported or dismissed"}, {name: "include_removed", typ: "boolean", desc: "also accounts the last scan no longer found"}}, resSchema: "PAMDiscoveredAccountList", successCode: "200", perm: authz.AccessRead},
	}
	return append(routes, a.pamServiceDependentRoutes()...)
}

func (a *API) discovery() (PAMDiscoveryService, error) {
	svc, ok := a.pam.(PAMDiscoveryService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return svc, nil
}

func pamDiscoveryNotFound(err error) error {
	switch {
	case errors.Is(err, store.ErrPAMDiscoverySourceNotFound):
		return errStatus(http.StatusNotFound, "discovery source not found")
	case errors.Is(err, store.ErrPAMDiscoveryRunNotFound):
		return errStatus(http.StatusNotFound, "discovery run not found")
	case errors.Is(err, store.ErrPAMDiscoveredAccountNotFound):
		return errStatus(http.StatusNotFound, "discovered account not found")
	}
	return err
}

func (a *API) listPAMDiscoverySources(w http.ResponseWriter, r *http.Request) {
	svc, err := a.discovery()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := svc.ListPAMDiscoverySources(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) savePAMDiscoverySource(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.discovery()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			IntervalSeconds int `json:"interval_seconds"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		saved, err := svc.SavePAMDiscoverySource(ctx, tenantID, principalSubject(ctx), r.PathValue("provider_id"), body.IntervalSeconds)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, saved, nil
	})
}

//trstctl:mutation
func (a *API) deletePAMDiscoverySource(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.discovery()
		if err != nil {
			return 0, nil, err
		}
		providerID := r.PathValue("provider_id")
		if err := svc.DeletePAMDiscoverySource(ctx, tenantID, principalSubject(ctx), providerID); err != nil {
			return 0, nil, pamDiscoveryNotFound(err)
		}
		return http.StatusOK, map[string]any{"provider_id": providerID, "deleted": true}, nil
	})
}

//trstctl:mutation
func (a *API) runPAMDiscovery(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.discovery()
		if err != nil {
			return 0, nil, err
		}
		run, err := svc.RunPAMDiscovery(ctx, tenantID, principalSubject(ctx), r.PathValue("provider_id"))
		if err != nil {
			return 0, nil, pamDiscoveryNotFound(err)
		}
		return http.StatusCreated, run, nil
	})
}

func (a *API) listPAMDiscoveryRuns(w http.ResponseWriter, r *http.Request) {
	svc, err := a.discovery()
	if err != nil {
		a.writePAMError(w, err)
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
		if err != nil || n < 1 || n > 500 {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be 1-500"))
			return
		}
		limit = n
	}
	items, err := svc.ListPAMDiscoveryRuns(r.Context(), tenantID, r.URL.Query().Get("provider_id"), limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) getPAMDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	svc, err := a.discovery()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	run, err := svc.GetPAMDiscoveryRun(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, pamDiscoveryNotFound(err))
		return
	}
	a.writeJSON(w, http.StatusOK, run)
}

func (a *API) listPAMDiscoveredAccounts(w http.ResponseWriter, r *http.Request) {
	svc, err := a.discovery()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	q := r.URL.Query()
	status := q.Get("status")
	if status != "" && status != "staged" && status != "imported" && status != "dismissed" {
		a.writeError(w, errStatus(http.StatusBadRequest, "status must be staged, imported or dismissed"))
		return
	}
	includeRemoved := false
	if raw := q.Get("include_removed"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "include_removed must be true or false"))
			return
		}
		includeRemoved = v
	}
	items, err := svc.ListPAMDiscoveredAccounts(r.Context(), tenantID, q.Get("provider_id"), status, includeRemoved)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) requestPAMDiscoveryImport(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.discovery()
		if err != nil {
			return 0, nil, err
		}
		var body PAMDiscoveryImportRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		review, err := svc.RequestPAMDiscoveryImport(ctx, tenantID, principalSubject(ctx), body)
		if err != nil {
			return 0, nil, pamDiscoveryNotFound(err)
		}
		return http.StatusAccepted, review, nil
	})
}

//trstctl:mutation
func (a *API) applyPAMDiscoveryImport(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.discovery()
		if err != nil {
			return 0, nil, err
		}
		var body PAMDiscoveryImportRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if body.RequestID != "" && body.RequestID != r.PathValue("request_id") {
			return 0, nil, errStatus(http.StatusBadRequest, "request_id in the body differs from the path")
		}
		body.RequestID = r.PathValue("request_id")
		imported, err := svc.ApplyPAMDiscoveryImport(ctx, tenantID, principalSubject(ctx), body)
		if err != nil {
			return 0, nil, pamDiscoveryNotFound(err)
		}
		return http.StatusOK, map[string]any{"items": imported}, nil
	})
}

//trstctl:mutation
func (a *API) dismissPAMDiscoveredAccount(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.discovery()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		account, err := svc.DismissPAMDiscoveredAccount(ctx, tenantID, principalSubject(ctx), r.PathValue("id"), body.Reason)
		if err != nil {
			return 0, nil, pamDiscoveryNotFound(err)
		}
		return http.StatusOK, account, nil
	})
}

func (a *API) listPAMImportedAccounts(w http.ResponseWriter, r *http.Request) {
	svc, err := a.discovery()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := svc.ListPAMImportedAccounts(r.Context(), tenantID, r.URL.Query().Get("folder"), r.URL.Query().Get("provider_id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
