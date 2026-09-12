// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
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

// ABACDenyEvaluator is the deny-only attribute overlay. It can veto a request
// that RBAC and the primary policy gate otherwise allow, but it never grants a
// permission by itself.
type ABACDenyEvaluator interface {
	EvaluateDeny(ctx context.Context, in policy.ABACInput) (policy.ABACDecision, error)
}

// ApprovalChecker is the retired resource/action-only compatibility seam. It cannot
// identify one immutable request, intent digest, target version, or evidence set, so
// production implementations must fail closed. New mutation paths use
// ExactApprovalChecker. It remains here only so older edition adapters fail safely
// instead of silently treating a standing boolean as reusable authority.
type ApprovalChecker interface {
	// IsApproved must not authorize a mutation. The production implementation always
	// returns false and directs callers to the exact one-shot authority contract.
	IsApproved(ctx context.Context, tenantID, resource, action, requester string) (approved bool, reason string)
}

// ApprovalIntent is the complete immutable context for one reviewer decision.
// TargetVersion is the current event-projected revision, not a caller-controlled
// counter. EvidenceRefs contain identifiers/digests only, never secret values.
type ApprovalIntent struct {
	TenantID          string
	ResourceKind      string
	ResourceID        string
	ResourceName      string
	Action            string
	Requester         string
	FromState         string
	ToState           string
	TargetVersion     uint64
	Reason            string
	EvidenceRefs      []string
	RequiredApprovals int
	TTL               time.Duration
}

type ApprovalAuthority struct {
	RequestID         string
	IntentDigest      string
	Requester         string
	ResourceKind      string
	ResourceID        string
	Action            string
	FromState         string
	ToState           string
	TargetVersion     uint64
	RequiredApprovals int
	Reason            string
	EvidenceRefs      []string
	Issuance          *store.OperationApprovalIssuanceBinding
	Disposition       ApprovalDisposition
}

// ApprovalDisposition is the closed-set requester-side state of an exact
// approval authority. Callers use it to distinguish an approval that can still
// make progress from a terminal authority that requires a new command identity.
type ApprovalDisposition string

const (
	ApprovalDispositionPending    ApprovalDisposition = "pending"
	ApprovalDispositionApproved   ApprovalDisposition = "approved"
	ApprovalDispositionDenied     ApprovalDisposition = "denied"
	ApprovalDispositionExpired    ApprovalDisposition = "expired"
	ApprovalDispositionSuperseded ApprovalDisposition = "superseded"
	ApprovalDispositionConsumed   ApprovalDisposition = "consumed"
	ApprovalDispositionDrifted    ApprovalDisposition = "drifted"
)

func (d ApprovalDisposition) Terminal() bool {
	switch d {
	case ApprovalDispositionDenied, ApprovalDispositionExpired,
		ApprovalDispositionSuperseded, ApprovalDispositionConsumed,
		ApprovalDispositionDrifted:
		return true
	default:
		return false
	}
}

// ExactApprovalChecker is the production event-sourced request/digest/version-bound
// contract. Returning approved only permits the caller to attempt the command; the
// command event projector must atomically consume the returned authority.
type ExactApprovalChecker interface {
	AuthorizeApproval(context.Context, ApprovalIntent) (ApprovalAuthority, bool, string)
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
	// ABAC is the deny overlay layered over RBAC and the primary policy gate. When
	// set, a matching deny policy vetoes the transition. Evaluation errors fail
	// closed.
	ABAC ABACDenyEvaluator
	// ABACEnvironment carries operator-provided deployment state (for example
	// change_window=true). It is copied into each ABAC input as input.env.
	ABACEnvironment map[string]string
	// ABACNow optionally supplies deterministic time for tests. Nil uses time.Now.
	ABACNow func() time.Time
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
	status   int
	detail   string
	approval *ApprovalAuthority
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
func (g MutationGate) check(ctx context.Context, p authz.Principal, tenantID, identityID string, to orchestrator.State, resource map[string]string) error {
	_, err := g.checkWithApproval(ctx, p, tenantID, identityID, to, resource, nil)
	return err
}

func (g MutationGate) checkWithApproval(ctx context.Context, p authz.Principal, tenantID, identityID string, to orchestrator.State, resource map[string]string, intent *ApprovalIntent) (*ApprovalAuthority, error) {
	action, privileged, ok := privilegedActionFor(to)
	if !ok {
		// Not an issue/deploy/revoke transition — out of this gate's scope; the
		// orchestrator's state machine still validates the edge.
		return nil, nil
	}

	target := authz.Scope{TenantID: tenantID}
	permission := permissionForPolicyAction(action)

	// (1) RA separation: certs:issue is required to issue or revoke. The requester
	// scope (certs:request) is deliberately insufficient — a requester cannot
	// self-issue (SEC-002, RED-004).
	if privileged && !p.Can(authz.CertsIssue, target) {
		return nil, &gateError{status: http.StatusForbidden,
			detail: "forbidden: a privileged " + string(action) + " requires the " + string(authz.CertsIssue) + " authority (the requester scope cannot self-issue)"}
	}

	// (2) ABAC deny overlay. RBAC has allowed the principal; ABAC can only narrow
	// that decision, never widen it.
	if g.ABAC != nil {
		in := g.abacInput(p, tenantID, identityID, action, permission, resource)
		d, err := g.ABAC.EvaluateDeny(ctx, in)
		switch {
		case errors.Is(err, bulkhead.ErrRejected):
			return nil, &gateError{status: http.StatusServiceUnavailable, detail: "ABAC engine busy; retry"}
		case err != nil:
			return nil, &gateError{status: http.StatusForbidden, detail: "denied by ABAC (evaluation error)"}
		case d.Deny:
			reason := d.Reason
			if reason == "" {
				reason = "denied by ABAC"
			}
			return nil, &gateError{status: http.StatusForbidden, detail: "denied by ABAC: " + reason}
		}
	}

	// (3) Policy default-deny. The engine is fail-closed, audited (AN-2), and
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
			return nil, &gateError{status: http.StatusServiceUnavailable, detail: "policy engine busy; retry"}
		case err != nil:
			// Any evaluation error denies (fail closed); the engine already audited it.
			return nil, &gateError{status: http.StatusForbidden, detail: "denied by policy (evaluation error)"}
		case !d.Allow:
			reason := d.Reason
			if reason == "" {
				reason = "denied by policy"
			}
			return nil, &gateError{status: http.StatusForbidden, detail: "denied by policy: " + reason}
		}
	}

	// (4) Dual control (distinct approver) for privileged actions, when enabled.
	if privileged && g.RequireApproval {
		if g.Checker == nil {
			// Misconfiguration must fail closed, never silently allow a privileged mint.
			return nil, &gateError{status: http.StatusForbidden, detail: "dual control required but no approval store is configured"}
		}
		exact, ok := g.Checker.(ExactApprovalChecker)
		if !ok || intent == nil {
			return nil, &gateError{status: http.StatusForbidden,
				detail: "dual control: exact request ID, intent digest, target version, and evidence are required"}
		}
		bound := *intent
		bound.TenantID = tenantID
		bound.ResourceID = identityID
		bound.Action = string(action)
		bound.Requester = p.Subject
		authority, approved, reason := exact.AuthorizeApproval(ctx, bound)
		if !approved {
			if reason == "" {
				reason = "a distinct approver must approve this " + string(action) + " (dual control)"
			}
			return nil, &gateError{status: http.StatusForbidden, detail: "dual control: " + reason, approval: &authority}
		}
		return &authority, nil
	}

	return nil, nil
}

func gateWithProfileApproval(g MutationGate, req orchestrator.ProfileApprovalRequirement) MutationGate {
	if req.ProfileName != "" {
		g.Profile = req.ProfileName
	}
	if req.RequiresApproval {
		g.RequireApproval = true
	}
	return g
}

func permissionForPolicyAction(action policy.Action) authz.Permission {
	switch action {
	case policy.ActionIssue, policy.ActionRevoke:
		return authz.CertsIssue
	case policy.ActionDeploy:
		return authz.IdentitiesWrite
	default:
		return ""
	}
}

func (g MutationGate) abacInput(p authz.Principal, tenantID, identityID string, action policy.Action, perm authz.Permission, resource map[string]string) policy.ABACInput {
	now := time.Now().UTC()
	if g.ABACNow != nil {
		now = g.ABACNow().UTC()
	}
	actorAttrs := map[string]string{
		"subject": p.Subject,
		"roles":   strings.Join(principalRoles(p), ","),
	}
	return policy.ABACInput{
		Permission: string(perm),
		Action:     action,
		TenantID:   tenantID,
		Profile:    g.Profile,
		Subject:    identityID,
		Actor:      p.Subject,
		ActorAttrs: actorAttrs,
		Resource:   copyStringMap(resource),
		Env:        copyStringMap(g.ABACEnvironment),
		Now:        now.Format(time.RFC3339),
		NowUnix:    now.Unix(),
		NowHourUTC: now.Hour(),
		NowWeekday: now.Weekday().String(),
	}
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
