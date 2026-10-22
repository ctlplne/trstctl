// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
)

// Route admission: tenant and special-route rate limiting and the target scope
// a request may act on. Split from api.go to keep the served file within its
// size budget.

func (a *API) allowTenantRequest(w http.ResponseWriter, r *http.Request, tenantID string) bool {
	if !a.allowTenantService(w, r, tenantID) {
		return false
	}
	if a.rateLimiter == nil {
		return true
	}
	allowed, retryAfter, err := a.rateLimiter.Allow(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return false
	}
	if allowed {
		return true
	}
	a.writeRateLimitExceeded(w, retryAfter)
	return false
}

func (a *API) allowSpecialRouteRequest(w http.ResponseWriter, r *http.Request, req specialRouteAbuseRequest) bool {
	if req.Source == "" {
		req.Source = requestClientIP(r)
	}
	if req.TenantID == "" {
		req.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if a.specialAbuse != nil {
		allowed, retryAfter := a.specialAbuse.allow(req)
		if !allowed {
			a.writeRateLimitExceeded(w, retryAfter)
			return false
		}
	}
	if req.TenantID != "" && !a.allowTenantRequest(w, r, req.TenantID) {
		return false
	}
	return true
}

func (a *API) writeRateLimitExceeded(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
	}
	a.writeProblem(w, problem.New(http.StatusTooManyRequests, "rate limit exceeded for this tenant"))
}

func requestTargetScope(principal authz.Principal, r *http.Request, scope routeScope) (authz.Scope, error) {
	target := authz.Scope{TenantID: principal.TenantID, Project: r.Header.Get("X-Project")}
	if scope == nil {
		return target, nil
	}
	scoped, err := scope(r)
	if err != nil {
		return authz.Scope{}, err
	}
	if scoped.TenantID != "" && scoped.TenantID != principal.TenantID {
		return authz.Scope{}, errStatus(http.StatusForbidden, "forbidden: cross-tenant scope")
	}
	if scoped.Project != "" {
		target.Project = scoped.Project
	}
	if scoped.Profile != "" {
		target.Profile = scoped.Profile
	}
	if scoped.Issuer != "" {
		target.Issuer = scoped.Issuer
	}
	return target, nil
}
