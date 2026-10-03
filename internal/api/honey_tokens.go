// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

var errHoneyTokenDetectorUnavailable = errors.New("api: honeytoken detector unavailable")

// observeHoneyTokenHash never authenticates the bearer. It records a first use
// and durable alert, or recognizes a previously triggered decoy. Normal token
// use takes no decoy lookup: guarded routes call this only after api_tokens
// misses; public routes call it only when a trst_ bearer is supplied.
func (a *API) observeHoneyTokenHash(r *http.Request, hash, pattern string) (bool, error) {
	if a.store == nil {
		return false, nil
	}
	decoy, err := a.store.LookupHoneyTokenByHash(r.Context(), hash)
	if store.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if decoy.State == "active" && a.orch != nil {
		// ServeMux returns patterns such as "GET /api/v1/access/roles". The
		// method has its own field in the immutable event and operator view.
		path := strings.TrimPrefix(pattern, r.Method+" ")
		if err := a.orch.RecordHoneyTokenTrigger(r.Context(), decoy.TenantID, decoy.ID, r.Method, path); err != nil {
			return true, err
		}
	}
	return true, nil
}

// Public routes bypass the normal RBAC resolver. Look up only presented trst_
// bearers on those routes so a decoy sent to OpenAPI or an auth endpoint is
// observed without doubling the database work of normal API-token requests.
func (a *API) refusePublicHoneyTokenBearer(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") == "" && r.Header.Get("X-Vault-Token") == "" {
		return false
	}
	_, pattern := a.mux.Handler(r)
	if a.guardedPatterns[pattern] {
		return false
	}
	raw := bearerTokenBytes(r)
	if len(raw) == 0 {
		return false
	}
	defer secret.Wipe(raw)
	if !bytes.HasPrefix(raw, []byte(auth.TokenPrefix)) {
		return false
	}
	hash, err := auth.HashAPIToken(raw)
	if err != nil {
		return false
	}
	// An unauthenticated caller can send arbitrary trst_ values to a public
	// route. Bound those pre-tenant lookups before they touch PostgreSQL.
	if a.specialAbuse != nil {
		allowed, retryAfter := a.specialAbuse.allow(specialRouteAbuseRequest{
			Source: requestClientIP(r), TokenKey: hash,
		})
		if !allowed {
			a.writeRateLimitExceeded(w, retryAfter)
			return true
		}
	}
	found, err := a.observeHoneyTokenHash(r, hash, pattern)
	if err != nil {
		a.logInternalError(w, err)
		a.writeProblem(localizedProblemWriter(w, r), problem.New(http.StatusServiceUnavailable, "credential detector unavailable"))
		return true
	}
	if !found {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	a.writeProblem(localizedProblemWriter(w, r), problem.New(http.StatusUnauthorized, "invalid bearer credential"))
	return true
}

type honeyTokenCreateRequest struct {
	Name      string `json:"name"`
	Placement string `json:"placement"`
}

func validHoneyTokenLabel(value string, maximum int) bool {
	if value == "" || utf8.RuneCountInString(value) > maximum {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
	}
	return true
}

type honeyTokenCreateResponse struct {
	store.HoneyToken
	Token secretJSONBytes `json:"token"`
}

func (r *honeyTokenCreateResponse) wipeSecrets() { r.Token.wipe() }

//trstctl:mutation
func (a *API) createHoneyToken(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req honeyTokenCreateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Name, req.Placement = strings.TrimSpace(req.Name), strings.TrimSpace(req.Placement)
		if !validHoneyTokenLabel(req.Name, 128) || !validHoneyTokenLabel(req.Placement, 256) {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "name (1-128 characters) and placement (1-256 characters) are required without control characters")
		}
		h, raw, err := a.orch.CreateHoneyToken(ctx, tenantID, req.Name, req.Placement)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, &honeyTokenCreateResponse{HoneyToken: h, Token: secretJSONBytes(raw)}, nil
	})
}

func (a *API) listHoneyTokens(w http.ResponseWriter, r *http.Request) {
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
	items, err := a.store.ListHoneyTokensPage(r.Context(), tenantID, after, limit)
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

func (a *API) getHoneyToken(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	h, err := a.store.GetHoneyToken(r.Context(), tenantID, r.PathValue("id"))
	if store.IsNotFound(err) {
		a.writeProblem(w, problem.New(http.StatusNotFound, "honeytoken not found"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	if h.Kind != "native" {
		a.writeProblem(w, problem.New(http.StatusNotFound, "honeytoken not found"))
		return
	}
	a.writeJSON(w, http.StatusOK, h)
}

//trstctl:mutation
func (a *API) revokeHoneyToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		h, err := a.store.GetHoneyToken(ctx, tenantID, id)
		if store.IsNotFound(err) {
			return 0, nil, errStatus(http.StatusNotFound, "honeytoken not found")
		}
		if err != nil {
			return 0, nil, err
		}
		if h.Kind != "native" {
			return 0, nil, errStatus(http.StatusNotFound, "honeytoken not found")
		}
		if h.State != "revoked" {
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
