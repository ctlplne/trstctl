// SPDX-License-Identifier: MPL-2.0

package api

// EXC-WIRE-03 — in-package unit tests for the served mutation gate's core logic.
// They exercise gate.check directly with fabricated principals and fakes (no
// Postgres), pinning the three invariants the served issue/deploy/revoke path must
// hold and that were library-only before this change (SEC-002, SEC-005, CORRECT-003,
// RED-004):
//
//   - default-deny policy: a privileged transition is denied unless the policy
//     explicitly allows it (fail closed), and a policy-pool shed denies (AN-7);
//   - RA separation: a privileged issue/revoke requires certs:issue, so a
//     certs:request-only requester cannot self-issue;
//   - dual control: when enabled, a distinct-approver approval is required and a
//     self-approval is refused.
//
// The served HTTP wiring and the real store-backed approval/policy path are covered
// by the integration tests (internal/server, against embedded Postgres).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/policy"
)

const gateTenant = "11111111-1111-1111-1111-111111111111"

// fakePolicy is a deterministic PolicyEvaluator: it returns the configured decision
// (and optional error) without compiling Rego, so the gate's translation of a
// decision to allow/deny is tested in isolation.
type fakePolicy struct {
	allow  bool
	reason string
	err    error
}

func (f fakePolicy) Evaluate(_ context.Context, _ policy.Input) (policy.Decision, error) {
	return policy.Decision{Allow: f.allow, Reason: f.reason}, f.err
}

type fakeABAC struct {
	deny   bool
	reason string
	err    error
	got    policy.ABACInput
}

func (f *fakeABAC) EvaluateDeny(_ context.Context, in policy.ABACInput) (policy.ABACDecision, error) {
	f.got = in
	return policy.ABACDecision{Deny: f.deny, Reason: f.reason}, f.err
}

// fakeChecker is a deterministic ApprovalChecker recording the last call so a test
// can assert the gate passes the right action/requester.
type fakeChecker struct {
	approved bool
	reason   string
	gotAction,
	gotRequester string
}

func (f *fakeChecker) IsApproved(_ context.Context, _, _, action, requester string) (bool, string) {
	f.gotAction, f.gotRequester = action, requester
	return f.approved, f.reason
}

// principalWith builds a principal in gateTenant holding exactly the given roles.
func principalWith(subject string, roles ...authz.Role) authz.Principal {
	grants := make([]authz.Grant, 0, len(roles))
	for _, r := range roles {
		grants = append(grants, authz.Grant{Role: r, Scope: authz.Scope{TenantID: gateTenant}})
	}
	return authz.Principal{TenantID: gateTenant, Subject: subject, Grants: grants}
}

var (
	roleIssuer    = authz.Role{Name: "issuer", Permissions: []authz.Permission{authz.CertsIssue, authz.IdentitiesWrite}}
	roleRequester = authz.Role{Name: "ra", Permissions: []authz.Permission{authz.CertsRequest, authz.IdentitiesWrite}}
)

func asGateErr(t *testing.T, err error) *gateError {
	t.Helper()
	if err == nil {
		return nil
	}
	var ge *gateError
	if !errors.As(err, &ge) {
		t.Fatalf("expected *gateError, got %T: %v", err, err)
	}
	return ge
}

// --- RA separation: the requester scope cannot self-issue --------------------

func TestGateRASeparationDeniesRequesterSelfIssue(t *testing.T) {
	// An empty gate still enforces the RA scope split for privileged transitions:
	// the policy/dual-control checks are off, but certs:issue is required to issue.
	g := MutationGate{}
	ctx := context.Background()

	// A certs:request-only principal (the RA requester) cannot drive an issue.
	reqr := principalWith("alice", roleRequester)
	err := g.check(ctx, reqr, gateTenant, "id-1", "issued", nil)
	ge := asGateErr(t, err)
	if ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("requester self-issue must be 403-denied, got %v", err)
	}

	// Same for a privileged revoke.
	if ge := asGateErr(t, g.check(ctx, reqr, gateTenant, "id-1", "revoked", nil)); ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("requester self-revoke must be 403-denied, got %v", ge)
	}

	// A principal holding certs:issue passes the RA gate (no policy/approval wired).
	issuer := principalWith("bob", roleIssuer)
	if err := g.check(ctx, issuer, gateTenant, "id-1", "issued", nil); err != nil {
		t.Fatalf("certs:issue holder should pass the RA gate, got %v", err)
	}
}

func TestGateDeployIsNotPrivileged(t *testing.T) {
	// A deploy is gated by policy when wired but is NOT a privileged issue/revoke, so
	// it does not require certs:issue and never needs dual control.
	g := MutationGate{}
	if err := g.check(context.Background(), principalWith("alice", roleRequester), gateTenant, "id-1", "deployed", nil); err != nil {
		t.Fatalf("deploy must not require certs:issue, got %v", err)
	}
}

func TestGateIgnoresNonGatedTransitions(t *testing.T) {
	// A transition that is neither issue/deploy/revoke (e.g. retired) is out of the
	// gate's scope and always allowed here (the orchestrator validates the edge).
	g := MutationGate{Policy: fakePolicy{allow: false}, RequireApproval: true, Checker: &fakeChecker{}}
	if err := g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "retired", nil); err != nil {
		t.Fatalf("a non-gated transition must pass, got %v", err)
	}
}

// --- Policy default-deny -----------------------------------------------------

func TestGatePolicyDeniesByDefault(t *testing.T) {
	g := MutationGate{Policy: fakePolicy{allow: false, reason: "no rule matched"}}
	// certs:issue holder, but policy denies -> 403.
	ge := asGateErr(t, g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil))
	if ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("policy deny must be 403, got %v", ge)
	}
}

func TestGatePolicyAllows(t *testing.T) {
	g := MutationGate{Policy: fakePolicy{allow: true}}
	if err := g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil); err != nil {
		t.Fatalf("policy allow + certs:issue should pass, got %v", err)
	}
}

func TestGatePolicyShedFailsClosed(t *testing.T) {
	// A saturated policy pool (AN-7) surfaces bulkhead.ErrRejected; the gate must
	// fail closed with a retryable 503, never allow.
	g := MutationGate{Policy: fakePolicy{allow: true, err: bulkhead.ErrRejected}}
	ge := asGateErr(t, g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil))
	if ge == nil || ge.status != http.StatusServiceUnavailable {
		t.Fatalf("a shed policy pool must fail closed with 503, got %v", ge)
	}
}

func TestGatePolicyErrorFailsClosed(t *testing.T) {
	g := MutationGate{Policy: fakePolicy{allow: true, err: errors.New("boom")}}
	ge := asGateErr(t, g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil))
	if ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("a policy evaluation error must fail closed (deny), got %v", ge)
	}
}

// --- ABAC deny overlay -------------------------------------------------------

func TestGateABACDeniesAfterRBAC(t *testing.T) {
	abac := &fakeABAC{deny: true, reason: "outside change window"}
	g := MutationGate{ABAC: abac, Policy: fakePolicy{allow: true}, Profile: "tls-server", ABACEnvironment: map[string]string{"change_window": "false"}}
	ge := asGateErr(t, g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", map[string]string{"env": "prod"}))
	if ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("ABAC deny must be 403, got %v", ge)
	}
	if abac.got.Permission != string(authz.CertsIssue) || abac.got.Resource["env"] != "prod" || abac.got.Env["change_window"] != "false" {
		t.Fatalf("ABAC input did not carry permission/resource/env: %+v", abac.got)
	}
}

func TestGateABACErrorFailsClosed(t *testing.T) {
	g := MutationGate{ABAC: &fakeABAC{err: errors.New("boom")}, Policy: fakePolicy{allow: true}}
	ge := asGateErr(t, g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil))
	if ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("ABAC error must fail closed with 403, got %v", ge)
	}
}

func TestGateABACShedFailsClosed(t *testing.T) {
	g := MutationGate{ABAC: &fakeABAC{err: bulkhead.ErrRejected}, Policy: fakePolicy{allow: true}}
	ge := asGateErr(t, g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil))
	if ge == nil || ge.status != http.StatusServiceUnavailable {
		t.Fatalf("ABAC shed must fail closed with 503, got %v", ge)
	}
}

func TestGuardABACDenyOverlayAfterRBAC(t *testing.T) {
	abac := &fakeABAC{deny: true, reason: "outside change window"}
	reader := authz.Role{Name: "owner-reader", Permissions: []authz.Permission{authz.OwnersRead}}
	principal := principalWith("carol", reader)
	api := New(nil, nil, nil,
		WithRoles(reader),
		WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
		WithABACDenyOverlay(abac, map[string]string{"change_window": "false"}, func() time.Time {
			return time.Date(2026, 6, 25, 13, 0, 0, 0, time.UTC)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "outside change window") {
		t.Fatalf("ABAC guard deny = %d body=%s, want 403 with reason", rr.Code, rr.Body.String())
	}
	if abac.got.Permission != string(authz.OwnersRead) || abac.got.Resource["request.path"] != "/api/v1/owners" || abac.got.Env["change_window"] != "false" || abac.got.NowHourUTC != 13 {
		t.Fatalf("ABAC guard input missing permission/resource/env/time: %+v", abac.got)
	}
}

// --- Dual control ------------------------------------------------------------

func TestGateDualControlRequiresApproval(t *testing.T) {
	checker := &fakeChecker{approved: false, reason: "needs a distinct approver"}
	g := MutationGate{Policy: fakePolicy{allow: true}, RequireApproval: true, Checker: checker}
	ge := asGateErr(t, g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil))
	if ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("dual control with no approval must be 403, got %v", ge)
	}
	if checker.gotAction != "issue" || checker.gotRequester != "bob" {
		t.Fatalf("gate must pass action=issue requester=bob to the checker, got action=%q requester=%q", checker.gotAction, checker.gotRequester)
	}
}

func TestGateDualControlAllowsWhenApproved(t *testing.T) {
	g := MutationGate{Policy: fakePolicy{allow: true}, RequireApproval: true, Checker: &fakeChecker{approved: true}}
	if err := g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil); err != nil {
		t.Fatalf("approved dual-control action should pass, got %v", err)
	}
}

func TestGateDualControlNoCheckerFailsClosed(t *testing.T) {
	// Misconfiguration (RequireApproval with no Checker) must never silently allow a
	// privileged mint.
	g := MutationGate{Policy: fakePolicy{allow: true}, RequireApproval: true}
	ge := asGateErr(t, g.check(context.Background(), principalWith("bob", roleIssuer), gateTenant, "id-1", "issued", nil))
	if ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("dual control with no approval store must fail closed, got %v", ge)
	}
}

// TestGateRABeatsApproval: the RA scope split is checked before policy/approval, so a
// requester-only principal is denied for lack of certs:issue even if (hypothetically)
// an approval existed — the requester can never self-issue.
func TestGateRABeatsApproval(t *testing.T) {
	g := MutationGate{Policy: fakePolicy{allow: true}, RequireApproval: true, Checker: &fakeChecker{approved: true}}
	ge := asGateErr(t, g.check(context.Background(), principalWith("alice", roleRequester), gateTenant, "id-1", "issued", nil))
	if ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("a requester (no certs:issue) must be denied regardless of approvals, got %v", ge)
	}
}

// TestBaseModuleDeniesIssueWithoutProfile wires the REAL policy engine (base module)
// into the gate to confirm the default-deny base policy denies an issue with no bound
// profile and allows it with one — the SEC-005 served behavior, end to end through the
// gate (no fake).
func TestBaseModuleDeniesIssueWithoutProfile(t *testing.T) {
	eng, err := policy.New(policy.Config{Module: policy.BaseModule})
	if err != nil {
		t.Fatalf("compile base policy: %v", err)
	}
	issuer := principalWith("bob", roleIssuer)
	ctx := context.Background()

	// No profile bound -> the base policy denies an issue.
	gNoProfile := MutationGate{Policy: eng}
	if ge := asGateErr(t, gNoProfile.check(ctx, issuer, gateTenant, "id-1", "issued", nil)); ge == nil || ge.status != http.StatusForbidden {
		t.Fatalf("base policy must deny issue without a bound profile, got %v", ge)
	}

	// A bound profile -> the base policy allows the issue.
	gProfile := MutationGate{Policy: eng, Profile: "tls-server"}
	if err := gProfile.check(ctx, issuer, gateTenant, "id-1", "issued", nil); err != nil {
		t.Fatalf("base policy must allow issue with a bound profile, got %v", err)
	}

	// Revoke is always allowed by the base policy (a credential must be revocable).
	if err := gProfile.check(ctx, issuer, gateTenant, "id-1", "revoked", nil); err != nil {
		t.Fatalf("base policy must allow revoke, got %v", err)
	}
}
