// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// Decoy files (Q6-O1): SSH private keys a host agent planted where no file
// was (trstctl-agent --decoy-ssh-keys). The agent registers each one over its
// channel and reports every open; each program that opens one raises one
// critical alert naming it and its host. Like the other decoys they are
// listed only to those who may plant decoys.

func (a *API) decoyFileRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "GET", path: "/api/v1/secrets/honeytokens/files", opID: "listDecoyFiles",
			summary: "List decoy files host agents planted and which programs opened them",
			handler: a.listDecoyFiles, query: []param{
				{name: "limit", typ: "integer", desc: "page size (1-100)"},
				{name: "cursor", typ: "string", desc: "opaque pagination cursor"},
			}, resSchema: "DecoyFileList", successCode: "200", perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/honeytokens/files/{id}/retire", opID: "retireDecoyFile",
			summary: "Stop alerting on a decoy file; the file stays on its host until the agent stops planting it",
			handler: a.retireDecoyFile, pathParams: idPath, resSchema: "DecoyFile", successCode: "200",
			mutation: true, perm: authz.SecretsWrite},
	}
}

func (a *API) listDecoyFiles(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	items, err := a.store.ListDecoyFilesPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	next := ""
	if len(items) == limit {
		next = encodeCursor(items[len(items)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (a *API) decoyFile(ctx context.Context, tenantID, id string) (store.HoneyToken, error) {
	h, err := a.store.GetHoneyToken(ctx, tenantID, id)
	if store.IsNotFound(err) || (err == nil && h.Kind != "file") {
		return store.HoneyToken{}, errStatus(http.StatusNotFound, "decoy file not found")
	}
	return h, err
}

//trstctl:mutation
func (a *API) retireDecoyFile(w http.ResponseWriter, r *http.Request) {
	if a.orch == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "decoys are not configured"))
		return
	}
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		h, err := a.decoyFile(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if h.State != "revoked" {
			if err := a.orch.RevokeHoneyToken(ctx, tenantID, id); err != nil {
				return 0, nil, err
			}
		}
		h, err = a.decoyFile(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, h, nil
	})
}
