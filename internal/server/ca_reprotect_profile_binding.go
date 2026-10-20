// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/decommission/reprotect"
	"trstctl.com/trstctl/internal/store"
)

// A re-protection job may have been queued before the active profile changed.
// Resolve the identity's current selection again while the issuance fence is
// held, then pin that exact revision for the signer. The immutable plan binds
// a policy name for new jobs; older plans had no such field and recover only
// after the current selection and certificate constraints are rechecked.
func (d *issuanceDispatcher) caReprotectProfileBinding(ctx context.Context, tenantID string, plan reprotect.CredentialPlan) (*store.OperationApprovalIssuanceBinding, error) {
	requirement, err := d.orch.ProfileApprovalRequirement(ctx, tenantID, plan.IdentityID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "CA re-protection identity policy unavailable: %v", err)
	}
	if requirement.ProfileName == "" && d.defaultProfile != "" {
		requirement, err = d.orch.ProfileApprovalRequirementByName(ctx, tenantID, d.defaultProfile)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "CA re-protection default policy unavailable: %v", err)
		}
	}
	if plan.ProfileName != "" && plan.ProfileName != requirement.ProfileName {
		return nil, status.Error(codes.FailedPrecondition, "CA re-protection selected policy differs from the reviewed plan")
	}
	binding := requirement.IssuanceBinding()
	binding.RequestedTTLSeconds = plan.TTLSeconds
	binding.EffectiveTTLSeconds = plan.TTLSeconds
	return binding, nil
}
