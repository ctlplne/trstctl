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

// A278: gateway pools. The gateways of a pool share sessions: a target bound
// to any member is served by the healthy, undrained member with the fewest
// live sessions when a session starts, and that member owns the session. A
// member that stops reporting is lost: new sessions go to the others and
// the sessions it owned end, bounded by their native deadlines.

// PAMGatewayMember is one gateway of a pool. Health, LastSeenAt and
// LiveSessions are read-only.
type PAMGatewayMember struct {
	AgentID  string `json:"agent_id"`
	Address  string `json:"address"`
	Draining bool   `json:"draining,omitempty"`
	// UpgradePending (read-only): an upgrade is queued for the gateway, so it
	// drains — takes no new sessions — and is handed the upgrade once its
	// live sessions have ended (A278 part 2).
	UpgradePending bool `json:"upgrade_pending,omitempty"`
	// Health is healthy, draining, lost (no report within
	// pam.gateway_lost_after) or offboarded.
	Health       string     `json:"health,omitempty"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	LiveSessions int        `json:"live_sessions"`
}

// PAMGatewayPool is a gateway pool at a revision.
type PAMGatewayPool struct {
	Name     string             `json:"name"`
	Members  []PAMGatewayMember `json:"members"`
	Revision int64              `json:"revision"`
	SavedBy  string             `json:"saved_by,omitempty"`
	SavedAt  time.Time          `json:"saved_at"`
}

// PAMGatewayPoolService keeps gateway pools; the served broker implements it.
type PAMGatewayPoolService interface {
	SavePAMGatewayPool(ctx context.Context, tenantID, actor string, p PAMGatewayPool) (PAMGatewayPool, error)
	ListPAMGatewayPools(ctx context.Context, tenantID string) ([]PAMGatewayPool, error)
	DeletePAMGatewayPool(ctx context.Context, tenantID, actor, name string, revision int64) error
}

func (a *API) pamGatewayPoolRoutes() []route {
	name := []param{pathString("name", "pool name: 1-64 lowercase letters, digits, - or _")}
	return []route{
		{method: "GET", path: "/api/v1/access/gateway-pools", opID: "listPAMGatewayPools", summary: "List gateway pools: the gateways that share sessions, each one's health and live sessions", handler: a.listPAMGatewayPools, resSchema: "PAMGatewayPoolList", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/gateway-pools/{name}", opID: "savePAMGatewayPool", summary: "Create a gateway pool, or replace one at the revision read: its members and which of them are draining", handler: a.savePAMGatewayPool, pathParams: name, reqSchema: "PAMGatewayPoolRequest", resSchema: "PAMGatewayPool", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "DELETE", path: "/api/v1/access/gateway-pools/{name}", opID: "deletePAMGatewayPool", summary: "Delete a gateway pool at the revision you read; its gateways then serve only the targets bound to each", handler: a.deletePAMGatewayPool, pathParams: name, query: []param{{required: true, name: "revision", typ: "integer", desc: "the pool's revision you read"}}, resSchema: "PAMGatewayPoolDeleted", successCode: "200", mutation: true, perm: authz.AccessTargetsWrite},
	}
}

func (a *API) gatewayPools() (PAMGatewayPoolService, error) {
	svc, ok := a.pam.(PAMGatewayPoolService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return svc, nil
}

func pamGatewayPoolNotFound(err error) error {
	if errors.Is(err, store.ErrPAMGatewayPoolNotFound) {
		return errStatus(http.StatusNotFound, "gateway pool not found")
	}
	return err
}

func (a *API) listPAMGatewayPools(w http.ResponseWriter, r *http.Request) {
	svc, err := a.gatewayPools()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := svc.ListPAMGatewayPools(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) savePAMGatewayPool(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.gatewayPools()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			Members  []PAMGatewayMember `json:"members"`
			Revision int64              `json:"revision"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		item, err := svc.SavePAMGatewayPool(ctx, tenantID, principal.Subject, PAMGatewayPool{Name: r.PathValue("name"), Members: body.Members, Revision: body.Revision})
		if err != nil {
			return 0, nil, pamGatewayPoolNotFound(err)
		}
		return http.StatusOK, item, nil
	})
}

//trstctl:mutation
func (a *API) deletePAMGatewayPool(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.gatewayPools()
		if err != nil {
			return 0, nil, err
		}
		revision, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
		if err != nil || revision < 1 {
			return 0, nil, errStatus(http.StatusBadRequest, "revision must be the pool's revision you read")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if err := svc.DeletePAMGatewayPool(ctx, tenantID, principal.Subject, r.PathValue("name"), revision); err != nil {
			return 0, nil, pamGatewayPoolNotFound(err)
		}
		return http.StatusOK, map[string]any{"name": r.PathValue("name"), "deleted": true}, nil
	})
}
