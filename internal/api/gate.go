package api

import (
	"context"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
)

// EXC-WIRE-03 — the served mutation gate. Until now the OPA/Rego default-deny
// policy engine (internal/policy), the RA separation (certs:request ≠ certs:issue,
// internal/authz), and dual-control approval (internal/approval) were library-only:
// modeled and unit-tested but enforced on no served route (SEC-002, SEC-005,
// CORRECT-003). RED-004 — "the loaded gun" — is precisely that the served mint was
// reachable without these checks. This gate wires them onto the served
// issue/deploy/revoke lifecycle transition so the running binary, not just a test,
// enforces them.
//
// The gate runs in the synchronous request handler (transitionIdentity), BEFORE the
// orchestrator records the lifecycle event and enqueues the outbox mint/revoke
// effect. That is the only seam where the authenticated principal is in context
// (the async outbox dispatcher has none), which the RA scope split and the
// distinct-approver check both require. It is tenant-scoped (AN-1): the policy
// input, the audit event, and the approval lookup all carry the request's tenant.

// PolicyEvaluator is the default-deny decision the gate consults on every served
// mutating lifecycle transition. *policy.Engine satisfies it. It is fail-closed,
// audited (AN-2), and runs under its own bulkhead (AN-7) — the engine owns those
// concerns, so a saturated policy pool or an evaluation error denies rather than
// blocking issuance.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, in policy.Input) (policy.Decision, error)
}

// ApprovalChecker reports whether a privileged action has a recorded approval by a
// principal DISTINCT from the requester (dual control). It returns approved=false
// with a human reason when the action is not yet approved, when the only approval
// is the requester's own (self-approval is rejected — the RED-004 / SEC-002
// defense), or when the approver is not permitted. The served implementation is
// event-store backed and tenant-scoped (AN-1); a nil checker disables dual control
// (the policy + RA-scope checks still apply).
type ApprovalChecker interface {
	// IsApproved reports whether the (tenant, resource, action) privileged action has
	// the required number of approvals by principals DISTINCT from the requester. The
	// action is the policy action ("issue"/"revoke"); requester is the principal
	// driving the mutation, and an approval by the requester themselves never counts.
	// The served implementation also records (idempotently) that this requester's
	// action awaits approval, so a distinct approver can be checked against them — and
	// so the requester can never be counted as their own approver.
	IsApproved(ctx context.Context, tenantID, resource, action, requester string) (approved bool, reason string)
}

// MutationGate enforces the served policy + RA-separation + dual-control checks on
// a mutating lifecycle transition. The zero value is a permissive no-op (used when
// nothing is wired, preserving the prior served behavior); a configured gate is
// fail-closed.
type MutationGate struct {
	// Policy is the default-deny engine. When set, every gated transition must be
	// explicitly allowed by policy or it is denied (fail closed). When nil, the
	// policy check is skipped (RA + dual-control still apply).
	Policy PolicyEvaluator
	// Profile is the certificate-profile name bound to the served issuance path, fed
	// into the policy input so a Rego rule can require a bound profile (the base
	// policy denies issue/deploy with an empty profile). Empty leaves input.profile
	// empty.
	Profile string
	// RequireApproval turns on dual control for privileged transitions (issue and
	// revoke). When true a Checker MUST be set, and the transition is denied unless a
	// distinct-approver approval is on record.
	RequireApproval bool
	// Checker backs the dual-control distinct-approver requirement. Required when
	// RequireApproval is true.
	Checker ApprovalChecker
}

// privilegedActionFor reports the policy action a lifecycle transition maps to and
// whether it is privileged (an issuance or a revocation — the credential-minting /
// trust-affecting operations the RA split and dual control protect). A transition
// that is neither an issue, a deploy, nor a revoke (e.g. requested→requested is not
// even valid; renew/retire are internal lifecycle moves) returns ok=false and the
// gate lets it through to the orchestrator's own state-machine validation.
//
// The mapping mirrors the orchestrator's side-effect edges (lifecycle.go):
//   - *→issued     → ActionIssue   (privileged: mints a credential — RED-004)
//   - issued→deployed → ActionDeploy (a deploy/push of the credential)
//   - *→revoked    → ActionRevoke  (privileged: a trust-affecting revocation)
func privilegedActionFor(to orchestrator.State) (action policy.Action, privileged, ok bool) {
	switch to {
	case orchestrator.StateIssued:
		return policy.ActionIssue, true, true
	case orchestrator.StateRevoked:
		return policy.ActionRevoke, true, true
	case orchestrator.StateDeployed:
		return policy.ActionDeploy, false, true
	default:
		return "", false, false
	}
}

// gateError carries the HTTP status a gate denial maps to so the handler renders
// the right problem+json (403 for an authz/policy/approval denial, 503 for a shed
// policy pool).
type gateError struct {
	status int
	detail string
}

func (e *gateError) Error() string { return e.detail }

// check runs the gate for a served mutating transition. It returns nil to allow,
// or a *gateError to deny (mapped to a problem+json status by the caller). It is
// fail-closed: a policy evaluation error, a saturated policy pool, an absent
// required approval, or a self-approval all deny.
//
// Order of checks (cheapest/most-specific first, but all fail-closed):
//  1. RA separation — a privileged transition (issue/revoke) requires the principal
//     to hold certs:issue in the target scope. A certs:request-only requester (the
//     ra-officer) therefore cannot self-issue: this is the served half of the RED-004
//     defense (the bootstrap token already withholds certs:issue; now the served mint
//     enforces it too).
//  2. Policy — the default-deny OPA/Rego gate must explicitly allow the action.
//  3. Dual control — when enabled, a distinct-approver approval must be on record.
func (g MutationGate) check(ctx context.Context, p authz.Principal, tenantID, identityID string, to orchestrator.State) error {
	action, privileged, ok := privilegedActionFor(to)
	if !ok {
		// Not an issue/deploy/revoke transition — out of this gate's scope; the
		// orchestrator's state machine still validates the edge.
		return nil
	}

	target := authz.Scope{TenantID: tenantID}

	// (1) RA separation: certs:issue is required to issue or revoke. The requester
	// scope (certs:request) is deliberately insufficient — a requester cannot
	// self-issue (SEC-002, RED-004).
	if privileged && !p.Can(authz.CertsIssue, target) {
		return &gateError{status: http.StatusForbidden,
			detail: "forbidden: a privileged " + string(action) + " requires the " + string(authz.CertsIssue) + " authority (the requester scope cannot self-issue)"}
	}

	// (2) Policy default-deny. The engine is fail-closed, audited (AN-2), and
	// bulkheaded (AN-7) internally; we translate its outcome to allow/deny here.
	if g.Policy != nil {
		in := policy.Input{
			Action:   action,
			TenantID: tenantID,
			Profile:  g.Profile,
			Subject:  identityID,
			Actor:    p.Subject,
		}
		d, err := g.Policy.Evaluate(ctx, in)
		switch {
		case errors.Is(err, bulkhead.ErrRejected):
			// AN-7: the policy pool shed — fail closed with a retryable status.
			return &gateError{status: http.StatusServiceUnavailable, detail: "policy engine busy; retry"}
		case err != nil:
			// Any evaluation error denies (fail closed); the engine already audited it.
			return &gateError{status: http.StatusForbidden, detail: "denied by policy (evaluation error)"}
		case !d.Allow:
			reason := d.Reason
			if reason == "" {
				reason = "denied by policy"
			}
			return &gateError{status: http.StatusForbidden, detail: "denied by policy: " + reason}
		}
	}

	// (3) Dual control (distinct approver) for privileged actions, when enabled.
	if privileged && g.RequireApproval {
		if g.Checker == nil {
			// Misconfiguration must fail closed, never silently allow a privileged mint.
			return &gateError{status: http.StatusForbidden, detail: "dual control required but no approval store is configured"}
		}
		approved, reason := g.Checker.IsApproved(ctx, tenantID, identityID, string(action), p.Subject)
		if !approved {
			if reason == "" {
				reason = "a distinct approver must approve this " + string(action) + " (dual control)"
			}
			return &gateError{status: http.StatusForbidden, detail: "dual control: " + reason}
		}
	}

	return nil
}
