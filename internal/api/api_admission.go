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
		req.Source = specialRouteSource(requestClientIP(r))
	}
	req.Family = specialRouteFamily(r.URL.Path)
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

func specialRouteFamily(path string) string {
	switch {
	case path == "/api/v1/editions":
		return "catalog"
	case strings.HasPrefix(path, "/auth/"):
		return "signin"
	case strings.HasPrefix(path, "/enroll/"):
		return "enrollment"
	case strings.HasPrefix(path, "/scim/") || strings.Contains(path, "/scim/"):
		return "scim"
	case strings.Contains(path, "/webhook"):
		return "webhook"
	default:
		return "other"
	}
}

func (a *API) writeRateLimitExceeded(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
	}
	a.writeProblem(w, problem.New(http.StatusTooManyRequests, "rate limit exceeded for this tenant"))
}

func (a *API) requestTargetScope(principal authz.Principal, r *http.Request, scope routeScope) (authz.Scope, error) {
	target := authz.Scope{TenantID: principal.TenantID}
	if scope != nil {
		scoped, err := scope(r)
		if err != nil {
			return authz.Scope{}, err
		}
		if scoped.TenantID != "" && scoped.TenantID != principal.TenantID {
			return authz.Scope{}, errStatus(http.StatusForbidden, "forbidden: cross-tenant scope")
		}
		target.Project = scoped.Project
		target.Profile = scoped.Profile
		target.Issuer = scoped.Issuer
	}
	// A project is an attribute of the targeted resource. The X-Project
	// header is caller-controlled and cannot grant RBAC scope or satisfy ABAC.
	if strings.HasPrefix(r.URL.Path, "/api/v1/secrets/projects/") {
		target.Project = strings.TrimSpace(r.PathValue("project"))
	} else if r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/projects" {
		project, err := jsonBodyStringField(r, "slug")
		if err != nil {
			return authz.Scope{}, err
		}
		target.Project = project
	} else if a.store != nil && strings.HasPrefix(r.URL.Path, "/api/v1/secrets/store/") {
		name := strings.TrimSpace(r.PathValue("name"))
		if name != "" {
			project, err := a.store.SecretScopeFor(r.Context(), principal.TenantID, name, principal.Subject)
			if err != nil {
				return authz.Scope{}, err
			}
			if project.InProject {
				target.Project = project.Project
			}
		}
	} else if a.store != nil && r.Method == http.MethodPost &&
		(r.URL.Path == "/api/v1/secrets/store" || r.URL.Path == "/api/v1/secrets/store/preview") {
		name, err := jsonBodyStringField(r, "name")
		if err != nil {
			return authz.Scope{}, err
		}
		project, err := a.store.SecretScopeFor(r.Context(), principal.TenantID, name, principal.Subject)
		if err != nil {
			return authz.Scope{}, err
		}
		if project.InProject {
			target.Project = project.Project
		}
	}
	return target, nil
}
