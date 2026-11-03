// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/store"
)

// Decoy database logins (Q6): bait PostgreSQL logins minted by a tenant's
// dynamic-secret provider that lists the role "decoy". Issuance reuses the
// durable lease engine, so a retried plant replays the same sealed DSN and never
// mints a second login. The leader's watcher reads the decoy database's session
// counter; any session is a use of the bait and raises one critical alert.

type databaseDecoyCreateRequest struct {
	Provider   string `json:"provider"`
	Name       string `json:"name"`
	Placement  string `json:"placement"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type databaseDecoyCreateResponse struct {
	store.HoneyToken
	Database string          `json:"database"`
	DSN      secretJSONBytes `json:"dsn"`
}

func (r *databaseDecoyCreateResponse) wipeSecrets() { r.DSN.wipe() }

func (a *API) databaseDecoyRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/secrets/honeytokens/databases", opID: "createDatabaseDecoy",
			summary: "Mint a decoy PostgreSQL login whose any use raises a critical alert; reveal its DSN once",
			handler: a.createDatabaseDecoy, reqSchema: "DatabaseDecoyCreateRequest", resSchema: "DatabaseDecoyCreateResponse",
			successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/honeytokens/databases", opID: "listDatabaseDecoys",
			summary: "List decoy database logins and whether one was used",
			handler: a.listDatabaseDecoys, query: []param{
				{name: "limit", typ: "integer", desc: "page size (1-100)"},
				{name: "cursor", typ: "string", desc: "opaque pagination cursor"},
			}, resSchema: "DatabaseDecoyList", successCode: "200", perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/honeytokens/databases/{id}/retire", opID: "retireDatabaseDecoy",
			summary: "Stop watching a decoy login and remove its role and database through the lease's revocation",
			handler: a.retireDatabaseDecoy, pathParams: idPath, resSchema: "DatabaseDecoy", successCode: "200",
			mutation: true, perm: authz.SecretsWrite},
	}
}

func databaseDecoyBinding(principal string, req databaseDecoyCreateRequest) (string, error) {
	material, err := json.Marshal(struct {
		Operation string                     `json:"operation"`
		Principal string                     `json:"principal"`
		Request   databaseDecoyCreateRequest `json:"request"`
	}{"database-decoy.create", principal, req})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
}

//trstctl:mutation
func (a *API) createDatabaseDecoy(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req databaseDecoyCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.Provider, req.Name, req.Placement = strings.TrimSpace(req.Provider), strings.TrimSpace(req.Name), strings.TrimSpace(req.Placement)
	if req.Provider == "" || !validHoneyTokenLabel(req.Name, 128) || !validHoneyTokenLabel(req.Placement, 256) || req.TTLSeconds <= 0 {
		a.writeError(w, errStatus(http.StatusUnprocessableEntity, "provider, name (1-128 characters), placement (1-256 characters) and a positive ttl_seconds are required"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := databaseDecoyBinding(principal, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateSealedDynamicLease(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		issuer, ok := engine.(boundDynamicLeaseIssuer)
		if !ok {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "durable dynamic-secret issuance is not configured")
		}
		lease, dsn, err := issuer.IssueBound(ctx, req.Provider, dynsecret.DecoyRole, time.Duration(req.TTLSeconds)*time.Second, key, binding)
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		if lease.BackendRef == "" {
			secret.Wipe(dsn)
			return 0, nil, errors.New("api: decoy lease has no login role")
		}
		planted, err := a.orch.RegisterDatabaseDecoy(ctx, tenantID, req.Name, req.Placement, req.Provider, lease.ID, lease.BackendRef)
		if err != nil {
			secret.Wipe(dsn)
			return 0, nil, err
		}
		return http.StatusCreated, &databaseDecoyCreateResponse{HoneyToken: planted,
			Database: dynsecret.DecoyDatabaseName(lease.BackendRef), DSN: secretJSONBytes(dsn)}, nil
	})
}

func (a *API) listDatabaseDecoys(w http.ResponseWriter, r *http.Request) {
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
	items, err := a.store.ListDatabaseDecoysPage(r.Context(), tenantID, after, limit)
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

//trstctl:mutation
func (a *API) retireDatabaseDecoy(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		h, err := a.store.GetHoneyToken(ctx, tenantID, id)
		if store.IsNotFound(err) || (err == nil && h.Kind != "database") {
			return 0, nil, errStatus(http.StatusNotFound, "decoy login not found")
		}
		if err != nil {
			return 0, nil, err
		}
		if h.State != "revoked" {
			// The lease owns the login: revoking it drops the role and its
			// database through the provider's durable revocation.
			engine, err := a.secrets.dynamicLeaseEngine(tenantID)
			if err != nil {
				return 0, nil, err
			}
			lease, err := getDynamicLeaseContext(ctx, engine, h.DBLeaseID)
			if err != nil {
				return 0, nil, dynamicLeaseError(err)
			}
			if lease.State != dynsecret.LeaseRevoked {
				if err := engine.Revoke(ctx, h.DBLeaseID); err != nil {
					return 0, nil, dynamicLeaseError(err)
				}
			}
			if err := a.orch.RevokeHoneyToken(ctx, tenantID, id); err != nil {
				return 0, nil, err
			}
		}
		h, err = a.store.GetHoneyToken(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, h, nil
	})
}
