// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/ee/billing"
)

// Per-customer quota administration on the provider plane (epic L2).
//
// Quota WRITES live here and only here. The limit caps what a customer may
// create, so the customer must not hold the pen: a tenant-reachable quota
// route would let the capped party raise their own cap, and the whole point
// of the row is that somebody else set it.

// QuotaStore is the durable half the plane writes through.
type QuotaStore interface {
	QuotaFor(ctx context.Context, tenantID string) (billing.Quota, error)
	SetQuota(ctx context.Context, q billing.Quota) error
}

// SetTenantQuota persists a customer's limits.
//
// Provision-class authority, deliberately: capacity is a provisioning
// decision, and an operator trusted to create a tenancy is the one trusted to
// size it. The tenant id on the stored row comes from the PATH the operator
// was authorized against — a body that named a different customer would turn
// an authorization on one tenancy into a write on another.
func (s *Service) SetTenantQuota(ctx context.Context, actor Operator, customerID string, q billing.Quota) error {
	if err := s.requireMutation(actor, true); err != nil {
		return err
	}
	if err := s.authorize(ctx, actor, customerID, OpProvision); err != nil {
		return err
	}
	if s.quotas == nil {
		// Fail closed AND say which piece is missing: a provider who wires
		// authentication and delegation and still cannot set a cap needs to
		// know the quota store is not attached, not to re-check their grants.
		return fmt.Errorf("%w: no durable quota store is attached on this deployment, so a cap "+
			"could not survive a restart; refusing to accept one that would silently evaporate",
			ErrForbidden)
	}
	q.TenantID = customerID
	q.UpdatedBy = actor.Email
	if err := s.quotas.SetQuota(ctx, q); err != nil {
		return err
	}
	return s.record(ctx, AuditEvent{Type: "provider.tenant.quota.set", TenantID: customerID,
		OperatorID: actor.ID, OperatorEmail: actor.Email, At: s.clock()})
}

// GetTenantQuota reads a customer's limits under the same delegation gate as
// every other customer-scoped read.
func (s *Service) GetTenantQuota(ctx context.Context, actor Operator, customerID string) (billing.Quota, error) {
	if err := s.requireOperator(actor); err != nil {
		return billing.Quota{}, err
	}
	if err := s.authorize(ctx, actor, customerID, OpRead); err != nil {
		return billing.Quota{}, err
	}
	if s.quotas == nil {
		return billing.Quota{}, fmt.Errorf("%w: no durable quota store is attached on this deployment", ErrForbidden)
	}
	return s.quotas.QuotaFor(ctx, customerID)
}
