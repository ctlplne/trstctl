// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

// issuanceProfileRequirement resolves the profile that governs an identity's
// issuance. An identity-level profile wins. Otherwise the configured served
// default is resolved when it exists, so a display label cannot stand in for
// the revision that will actually govern signing; a configured label without a
// stored revision is an error, never approval evidence, so it fails before any
// approval request could advertise authority the dispatcher must reject.
func (a *API) issuanceProfileRequirement(ctx context.Context, tenantID, identityID, servedProfile string) (orchestrator.ProfileApprovalRequirement, error) {
	req, err := a.orch.ProfileApprovalRequirement(ctx, tenantID, identityID)
	if err != nil || req.ProfileName != "" || servedProfile == "" {
		return req, err
	}
	return a.orch.ProfileApprovalRequirementByName(ctx, tenantID, servedProfile)
}

// gateOperatorTransition runs the served mutation gate (RA separation, the
// ABAC deny overlay, the default-deny policy and dual control) for an issue or
// revoke that an operator action makes outside the identity transition route:
// remediation playbooks and NHI decommission. Without it those actions were a
// way around the approvals the direct route requires. Such an action carries
// no exact approval, so where dual control applies it is refused, and the
// refusal names the route that can carry one. A denial is an *apiError with
// the gate's status; any other error passes through.
func (a *API) gateOperatorTransition(ctx context.Context, p authz.Principal, tenantID, identityID string, to orchestrator.State) error {
	gate := a.gate
	if to == orchestrator.StateIssued && a.orch != nil {
		profileReq, err := a.issuanceProfileRequirement(ctx, tenantID, identityID, gate.Profile)
		if err != nil {
			return err
		}
		gate = gateWithProfileApproval(gate, profileReq)
	}
	var resourceAttrs map[string]string
	if gate.ABAC != nil {
		var err error
		resourceAttrs, err = a.identityABACResourceAttrs(ctx, tenantID, identityID)
		if err != nil {
			return err
		}
		resourceAttrs["transition.to"] = string(to)
	}
	err := gate.check(ctx, p, tenantID, identityID, to, resourceAttrs)
	var ge *gateError
	if !errors.As(err, &ge) {
		return err
	}
	detail := ge.detail
	if ge.exactApprovalRequired {
		detail += "; this action cannot carry an exact approval: apply the " + string(to) +
			" through POST /api/v1/identities/{id}/transitions and have a distinct approver approve it"
	}
	return errStatus(ge.status, detail)
}

// operatorGateRefusal reports whether err is the gate's refusal (as opposed
// to a shed policy pool or another failure) and its operator-facing text.
func operatorGateRefusal(err error) (string, bool) {
	var ae *apiError
	if errors.As(err, &ae) && ae.status == http.StatusForbidden {
		return ae.detail, true
	}
	return "", false
}
