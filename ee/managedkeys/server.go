// SPDX-License-Identifier: LicenseRef-trstctl-EE

package managedkeys

import (
	"context"

	"trstctl.com/trstctl/internal/api"
)

// approvalGate adapts the shared event/store-backed distinct-approver checker
// to destructive managed-key command admission. It runs before the requested
// event/outbox row is created, so a denied action cannot reach the signer.
type approvalGate struct{ checker api.ApprovalChecker }

func (g approvalGate) IsApproved(ctx context.Context, tenantID, keyID, action, requester string) (bool, string) {
	return g.checker.IsApproved(ctx, tenantID, keyID, action, requester)
}
