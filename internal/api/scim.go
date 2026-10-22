// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// SCIMConfig carries the core extension contract; the licensed implementation
// owns protocol parsing and provisioning. Tokens alone never mount a handler.
type SCIMConfig struct {
	NewHandler func(SCIMConfig, SCIMHandlerDeps) http.Handler
	// NewWriteback builds the directory writeback worker (A73) when at least
	// one token names a writeback endpoint; nil leaves local member changes
	// unpushed, as before. The licensed implementation holds the outbound
	// bearers; core only routes the outbox rows to it.
	NewWriteback func(SCIMWritebackDeps) SCIMWritebackHandler
	Enabled      bool
	Tokens       []SCIMToken
}

type SCIMToken struct {
	SubjectAttribute string
	Name             string
	TenantID         string
	TokenHash        string
	// WritebackEndpoint is the directory's SCIM endpoint this token writes
	// back to; empty means no writeback for its tenant.
	WritebackEndpoint string
}

// SCIMWritebackDeps is what the writeback worker reads and records with.
type SCIMWritebackDeps struct {
	Store        *store.Store
	Orchestrator *orchestrator.Orchestrator
	HTTPClient   *http.Client
}

// SCIMWritebackHandler delivers one scim.writeback outbox row.
type SCIMWritebackHandler interface {
	Deliver(ctx context.Context, m orchestrator.Message) error
}

// SCIMHandlerDeps preserves the shared mutation spine and route-admission
// checks. The attached implementation cannot bypass tenant service/rate limits.
type SCIMHandlerDeps struct {
	Store        *store.Store
	Orchestrator *orchestrator.Orchestrator
	Idempotency  *orchestrator.Idempotency
	Roles        *authz.Registry
	AllowRequest func(http.ResponseWriter, *http.Request, string, string) bool
}

func WithSCIM(cfg SCIMConfig) Option { return func(c *config) { c.scim = &cfg } }

func (a *API) buildSCIMHandler() http.Handler {
	if a.scim == nil || !a.scim.Enabled || a.scim.NewHandler == nil {
		return nil
	}
	return a.scim.NewHandler(*a.scim, SCIMHandlerDeps{
		Store: a.store, Orchestrator: a.orch, Idempotency: a.idem, Roles: a.roles,
		AllowRequest: func(w http.ResponseWriter, r *http.Request, tenantID, tokenKey string) bool {
			return a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{TenantID: tenantID, TokenKey: tokenKey})
		},
	})
}
