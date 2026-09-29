// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
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
	return a.recordReason(r, principal, permission, "route permission is not granted")
}

// recordReason is record with a specific denial reason, for refusals that are
// not a missing route permission (for example a delegated token's approval).
func (a *authzDenialAudit) recordReason(r *http.Request, principal authz.Principal, permission authz.Permission, reason string) string {
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
		Decision: "deny", Reason: reason, Roles: roles,
	})
	if err != nil {
		return "unavailable"
	}
	return "recorded"
}

// delegatedApprovalRefusal explains why a delegated token cannot approve.
const delegatedApprovalRefusal = "this API token was minted for its subject by another person, so it cannot approve or deny on their behalf; approve with your own sign-in or a token you minted yourself"

// refuseDelegatedApproval keeps approvals personal (F262). A token one person
// minted for another subject may do that subject's work, but counting its vote
// would let the minter act as two people in a dual-control decision. The route
// guard has already authenticated and authorized the caller.
func (a *API) refuseDelegatedApproval(perm authz.Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if principal, ok := r.Context().Value(principalCtxKey).(authz.Principal); ok && principal.Delegated {
			w.Header().Set("X-Trstctl-Audit-Status", a.denialAudit.recordReason(r, principal, perm, "delegated API token cannot approve on its subject's behalf"))
			a.writeProblem(w, problem.New(http.StatusForbidden, delegatedApprovalRefusal))
			return
		}
		h(w, r)
	}
}
