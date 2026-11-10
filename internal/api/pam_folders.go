// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// A261 part 3: account folders. A folder names the access template every
// account in it takes: a session request or check-out for a target in the
// folder carries the template's reason, approvals and longest length (and its
// recording rule), and a request naming another template is refused.

// PAMFolder is an account folder.
type PAMFolder struct {
	Name        string    `json:"name"`
	TemplateID  string    `json:"template_id"`
	Description string    `json:"description,omitempty"`
	Targets     int       `json:"targets"`
	Revision    int64     `json:"revision"`
	SavedBy     string    `json:"saved_by,omitempty"`
	SavedAt     time.Time `json:"saved_at"`
}

// PAMFolderService keeps folders; the served broker implements it.
type PAMFolderService interface {
	SavePAMFolder(ctx context.Context, tenantID, actor string, f PAMFolder) (PAMFolder, error)
	ListPAMFolders(ctx context.Context, tenantID string) ([]PAMFolder, error)
	DeletePAMFolder(ctx context.Context, tenantID, actor, name string, revision int64) error
	SetPAMTargetFolder(ctx context.Context, tenantID, actor, targetType, id, folder string) (PAMTarget, error)
}

func (a *API) pamFolderRoutes() []route {
	name := []param{pathString("name", "folder name: 1-64 lowercase letters, digits, - or _")}
	return []route{
		{method: "GET", path: "/api/v1/access/folders", opID: "listPAMFolders", summary: "List account folders: the access template every account in each takes", handler: a.listPAMFolders, resSchema: "PAMFolderList", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/folders/{name}", opID: "savePAMFolder", summary: "Create an account folder, or replace one at the revision read; a policy change requires a fresh access review", handler: a.savePAMFolder, pathParams: name, reqSchema: "PAMFolderRequest", resSchema: "PAMFolder", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "DELETE", path: "/api/v1/access/folders/{name}", opID: "deletePAMFolder", summary: "Delete an empty account folder at the revision you read", handler: a.deletePAMFolder, pathParams: name, query: []param{{required: true, name: "revision", typ: "integer", desc: "the folder's revision you read"}}, resSchema: "PAMFolderDeleted", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "POST", path: "/api/v1/access/targets/{target_type}/{id}/folder", opID: "setPAMTargetFolder", summary: "Move a tenant privileged access target into a folder, whose template its requests take, or out of one", handler: a.setPAMTargetFolder, pathParams: []param{pathString("target_type", "registered target type"), pathString("id", "target id")}, reqSchema: "PAMTargetFolderRequest", resSchema: "PAMTarget", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
	}
}

func (a *API) folders() (PAMFolderService, error) {
	svc, ok := a.pam.(PAMFolderService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return svc, nil
}

func pamFolderNotFound(err error) error {
	switch {
	case errors.Is(err, store.ErrPAMFolderNotFound):
		return errStatus(http.StatusNotFound, "folder not found")
	case errors.Is(err, store.ErrPAMTargetNotFound):
		return errStatus(http.StatusNotFound, "PAM target not found")
	}
	return err
}

func (a *API) listPAMFolders(w http.ResponseWriter, r *http.Request) {
	svc, err := a.folders()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := svc.ListPAMFolders(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) savePAMFolder(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.folders()
		if err != nil {
			return 0, nil, err
		}
		var body PAMFolder
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		body.Name = r.PathValue("name")
		item, err := svc.SavePAMFolder(ctx, tenantID, principal.Subject, body)
		if err != nil {
			return 0, nil, pamTemplateNotFound(err)
		}
		return http.StatusOK, item, nil
	})
}

//trstctl:mutation
func (a *API) deletePAMFolder(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.folders()
		if err != nil {
			return 0, nil, err
		}
		revision, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
		if err != nil || revision < 1 {
			return 0, nil, errStatus(http.StatusBadRequest, "revision must be the folder's revision you read")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if err := svc.DeletePAMFolder(ctx, tenantID, principal.Subject, r.PathValue("name"), revision); err != nil {
			return 0, nil, pamFolderNotFound(err)
		}
		return http.StatusOK, map[string]any{"name": r.PathValue("name"), "deleted": true}, nil
	})
}

//trstctl:mutation
func (a *API) setPAMTargetFolder(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.folders()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			Folder string `json:"folder"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "authenticated registrar required")
		}
		item, err := svc.SetPAMTargetFolder(ctx, tenantID, principal.Subject, r.PathValue("target_type"), r.PathValue("id"),
			strings.TrimSpace(body.Folder))
		if err != nil {
			return 0, nil, pamFolderNotFound(err)
		}
		return http.StatusOK, item, nil
	})
}
