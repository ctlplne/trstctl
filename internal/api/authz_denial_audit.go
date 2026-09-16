// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

const authzDenialAuditConcurrency = 8
const authzDenialAuditTimeout = time.Second

// authzDenialAudit has a separate admission budget from login/enrollment so a
// valid but unprivileged principal cannot exhaust those routes. Requests never
// queue for an audit slot. A full/unavailable audit path cannot authorize them.
type authzDenialAudit struct {
	limiter        *specialRouteAbuseLimiter
	slots          chan struct{}
	timeout        time.Duration
	appendDecision func(context.Context, string, orchestrator.AuthzDecision) error
}

func newAuthzDenialAudit(limits SpecialRouteAbuseLimits, orch *orchestrator.Orchestrator) *authzDenialAudit {
	a := &authzDenialAudit{limiter: newSpecialRouteAbuseLimiter(limits), slots: make(chan struct{}, authzDenialAuditConcurrency), timeout: authzDenialAuditTimeout}
	if orch != nil {
		a.appendDecision = orch.RecordAuthzDecision
	}
	return a
}

// record is called only after resolving the authenticated tenant and subject,
// checking any tenant header, validating CSRF and resolving the route scope.
// Record the registered route pattern, never URL/query/body/credential material.
// An unconfirmed append is reported as unavailable: cancellation can race an
// already committed event, so that status must not be read as proof of absence.
func (a *authzDenialAudit) record(r *http.Request, principal authz.Principal, permission authz.Permission) string {
	if a == nil || a.appendDecision == nil || principal.TenantID == "" || principal.Subject == "" {
		return "unavailable"
	}
	allowed, _ := a.limiter.allow(specialRouteAbuseRequest{Source: requestClientIP(r), TokenKey: principal.TenantID + "\x00" + principal.Subject, TenantID: principal.TenantID})
	if !allowed {
		return "rate_limited"
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		return "busy"
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.timeout)
	defer cancel()
	roles := principalRoles(principal)
	ctx = events.ContextWithActor(ctx, events.Actor{Subject: principal.Subject, Roles: roles})
	err := a.appendDecision(ctx, principal.TenantID, orchestrator.AuthzDecision{
		Actor: principal.Subject, Permission: string(permission), Resource: "api_route", Target: r.Pattern,
		Decision: "deny", Reason: "route permission is not granted", Roles: roles,
	})
	if err != nil {
		return "unavailable"
	}
	return "recorded"
}
