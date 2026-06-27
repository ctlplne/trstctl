package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestProfileRequirementTurnsOnDualControl(t *testing.T) {
	scope := authz.Scope{TenantID: gateTenant}
	principal := authz.Principal{
		TenantID: gateTenant,
		Subject:  "issuer",
		Grants:   []authz.Grant{{Role: roleIssuer, Scope: scope}},
	}

	checker := &fakeChecker{approved: false}
	gate := gateWithProfileApproval(MutationGate{Checker: checker}, orchestrator.ProfileApprovalRequirement{
		ProfileName:      "prod",
		RequiresApproval: true,
	})
	err := gate.check(context.Background(), principal, gateTenant, "identity-1", orchestrator.StateIssued, nil)
	ge := asGateErr(t, err)
	if ge.status != http.StatusForbidden || !strings.Contains(ge.detail, "dual control") {
		t.Fatalf("profile-gated issuance err = %v, want dual-control 403", err)
	}
	if checker.gotAction != "issue" || checker.gotRequester != "issuer" {
		t.Fatalf("checker saw action/requester = %q/%q", checker.gotAction, checker.gotRequester)
	}

	checker.approved = true
	if err := gate.check(context.Background(), principal, gateTenant, "identity-1", orchestrator.StateIssued, nil); err != nil {
		t.Fatalf("approved profile-gated issuance denied: %v", err)
	}

	direct := gateWithProfileApproval(MutationGate{Checker: checker}, orchestrator.ProfileApprovalRequirement{
		ProfileName:      "standard",
		RequiresApproval: false,
	})
	checker.reason = errors.New("checker should not be called for normal profile").Error()
	checker.approved = false
	checker.gotAction = ""
	checker.gotRequester = ""
	if err := direct.check(context.Background(), principal, gateTenant, "identity-2", orchestrator.StateIssued, nil); err != nil {
		t.Fatalf("normal profile issuance should not require approval: %v", err)
	}
	if checker.gotAction != "" || checker.gotRequester != "" {
		t.Fatalf("normal profile called checker with action/requester = %q/%q", checker.gotAction, checker.gotRequester)
	}
}
