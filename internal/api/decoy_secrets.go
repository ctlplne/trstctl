// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// Secret decoys (Q6): an application secret registered as bait. Planting is two
// steps on purpose: the secret is written through the ordinary create path, so
// it is indistinguishable from any other, and then registered here. The
// registry needs secrets:write, the planting permission, because a caller with
// only secrets:read is exactly who must not learn which secrets are bait.
//
// Every value read served to a caller (the native read, a historical version,
// reference resolution and the Vault-compatible KV read) is observed. Listing
// names, reading metadata, the access preview and trstctl's own scans read no
// value through these paths and never alert.

type decoySecretRegisterRequest struct {
	SecretName string `json:"secret_name"`
	Name       string `json:"name"`
	Placement  string `json:"placement"`
}

func (a *API) decoySecretRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/secrets/honeytokens/secrets", opID: "registerDecoySecret",
			summary: "Register a stored application secret as a decoy whose every read alerts, naming the reader",
			handler: a.registerDecoySecret, reqSchema: "DecoySecretRegisterRequest", resSchema: "DecoySecret",
			successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/honeytokens/secrets", opID: "listDecoySecrets",
			summary: "List decoy secrets and who first read each one",
			handler: a.listDecoySecrets, query: []param{
				{name: "limit", typ: "integer", desc: "page size (1-100)"},
				{name: "cursor", typ: "string", desc: "opaque pagination cursor"},
			}, resSchema: "DecoySecretList", successCode: "200", perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/honeytokens/secrets/{id}", opID: "getDecoySecret",
			summary: "Investigate one decoy secret and its first read",
			handler: a.getDecoySecret, pathParams: idPath, resSchema: "DecoySecret", successCode: "200", perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/honeytokens/secrets/{id}/retire", opID: "retireDecoySecret",
			summary: "Stop watching a decoy secret; the secret itself is left in place",
			handler: a.retireDecoySecret, pathParams: idPath, resSchema: "DecoySecret", successCode: "200",
			mutation: true, perm: authz.SecretsWrite},
	}
}

//trstctl:mutation
func (a *API) registerDecoySecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req decoySecretRegisterRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.SecretName = strings.TrimSpace(req.SecretName)
		req.Name, req.Placement = strings.TrimSpace(req.Name), strings.TrimSpace(req.Placement)
		if req.SecretName == "" || len(req.SecretName) > 1024 {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "secret_name (1-1024 characters) is required")
		}
		if !validHoneyTokenLabel(req.Name, 128) || !validHoneyTokenLabel(req.Placement, 256) {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "name (1-128 characters) and placement (1-256 characters) are required without control characters")
		}
		if _, err := a.secrets.be.Store.GetSecret(ctx, tenantID, req.SecretName); errors.Is(err, store.ErrSecretNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "no such secret; create the bait secret through the secret store first, then register it")
		} else if err != nil {
			return 0, nil, err
		}
		if _, live, err := a.store.LookupLiveDecoySecret(ctx, tenantID, req.SecretName); err != nil {
			return 0, nil, err
		} else if live {
			return 0, nil, errStatus(http.StatusConflict, "this secret is already a decoy")
		}
		h, err := a.orch.RegisterDecoySecret(ctx, tenantID, req.Name, req.Placement, req.SecretName)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, h, nil
	})
}

func (a *API) listDecoySecrets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	items, err := a.store.ListDecoySecretsPage(r.Context(), tenantID, after, limit)
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

func (a *API) decoySecret(ctx context.Context, tenantID, id string) (store.HoneyToken, error) {
	h, err := a.store.GetHoneyToken(ctx, tenantID, id)
	if store.IsNotFound(err) || (err == nil && h.Kind != "secret") {
		return store.HoneyToken{}, errStatus(http.StatusNotFound, "decoy secret not found")
	}
	return h, err
}

func (a *API) getDecoySecret(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	h, err := a.decoySecret(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, h)
}

//trstctl:mutation
func (a *API) retireDecoySecret(w http.ResponseWriter, r *http.Request) {
	if a.orch == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "decoys are not configured"))
		return
	}
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		h, err := a.decoySecret(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if h.State != "revoked" {
			if err := a.orch.RevokeHoneyToken(ctx, tenantID, id); err != nil {
				return 0, nil, err
			}
		}
		h, err = a.decoySecret(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, h, nil
	})
}

// observeDecoySecretRead records a served value read of any decoy among names
// before the value is written to the caller. A read that cannot be recorded is
// refused, so a decoy value is never served unwatched.
func (a *API) observeDecoySecretRead(r *http.Request, tenantID string, names ...string) error {
	if a.orch == nil || a.store == nil {
		return nil
	}
	reader := ""
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		id, live, err := a.store.LookupLiveDecoySecret(r.Context(), tenantID, name)
		if err != nil {
			return err
		}
		if !live {
			continue
		}
		if reader == "" {
			if reader, err = requestPrincipalSubject(r.Context()); err != nil {
				return err
			}
		}
		route := strings.TrimPrefix(r.Pattern, r.Method+" ")
		if err := a.orch.RecordDecoySecretRead(r.Context(), tenantID, id, reader, r.Method, route); err != nil {
			return err
		}
	}
	return nil
}

// decoyReadCollector gathers every secret a reference resolution opened, so a
// decoy reached through ${secret.path} is observed like a direct read. Only the
// served read installs it; other resolvers (the access preview) never do.
type decoyReadCollectorKey struct{}

func withDecoyReadCollector(ctx context.Context) (context.Context, *[]string) {
	names := &[]string{}
	return context.WithValue(ctx, decoyReadCollectorKey{}, names), names
}

func collectDecoyRead(ctx context.Context, name string) {
	if names, ok := ctx.Value(decoyReadCollectorKey{}).(*[]string); ok {
		*names = append(*names, name)
	}
}
