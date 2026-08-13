// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/license"
)

// ListOperatorAccess returns the full Provider authority inventory only to a
// currently MFA-authenticated Provider admin. Ordinary delegated operators do
// not get to enumerate their coworkers or other customers' historical grants.
func (s *Service) ListOperatorAccess(ctx context.Context, actor Operator) ([]OperatorAccess, error) {
	if err := s.requireAdminAccessRead(actor); err != nil {
		return nil, err
	}
	if s.access == nil {
		return nil, errors.New("provider: operator access store is not configured")
	}
	return s.access.ListOperatorAccess(ctx)
}

// ListAccessCustomers returns the roster the access editor may grant. It is
// deliberately separate from ListTenants: that normal operator view is
// delegation-filtered, while an administrator cannot assign a not-yet-granted
// customer if the selector hides it. Admin + current MFA is the boundary.
func (s *Service) ListAccessCustomers(ctx context.Context, actor Operator) ([]Tenant, error) {
	if err := s.requireAdminAccessRead(actor); err != nil {
		return nil, err
	}
	return s.store.ListTenants(ctx)
}

func (s *Service) requireAdminAccessRead(actor Operator) error {
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		return ErrUnlicensed
	}
	if err := s.requireOperator(actor); err != nil || actor.Role != OperatorAdmin {
		return ErrForbidden
	}
	return nil
}

func (s *Service) GrantDelegations(
	ctx context.Context,
	actor Operator,
	operatorID string,
	customerID string,
	operations []Operation,
	expiresAt time.Time,
) (OperatorAccess, error) {
	if err := s.requireMutation(actor, true); err != nil {
		return OperatorAccess{}, err
	}
	if s.access == nil {
		return OperatorAccess{}, errors.New("provider: operator access store is not configured")
	}
	operatorID, customerID = strings.TrimSpace(operatorID), strings.TrimSpace(customerID)
	if operatorID == "" || customerID == "" {
		return OperatorAccess{}, errors.New("provider: operator_id and customer_id are required")
	}
	identity, err := s.access.ResolveOperator(ctx, operatorID)
	if err != nil {
		return OperatorAccess{}, err
	}
	if !identity.Active {
		return OperatorAccess{}, fmt.Errorf("%w: an inactive operator cannot receive authority", ErrForbidden)
	}
	if _, err := s.store.Tenant(ctx, customerID); err != nil {
		return OperatorAccess{}, err
	}
	operations, err = normalizeOperations(operations)
	if err != nil {
		return OperatorAccess{}, err
	}
	now := s.clock().UTC()
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC()
		if !expiresAt.After(now) {
			return OperatorAccess{}, errors.New("provider: delegation expiry must be in the future")
		}
	}
	delegations := make([]DelegationMutation, 0, len(operations))
	for _, operation := range operations {
		delegations = append(delegations, DelegationMutation{
			OperatorID: identity.ID, CustomerID: customerID, Operation: operation,
			GrantedBy: actor.ID, Source: "console", ExpiresAt: expiresAt,
		})
	}
	if _, err := s.emit(ctx, EventDelegationGranted, customerID, AuthorityEvent{
		Delegations: delegations, EffectiveAt: now,
		Audit: AuditEvent{Type: EventDelegationGranted, TenantID: customerID,
			OperatorID: actor.ID, OperatorEmail: actor.Email, Subject: identity.ID, At: now},
	}); err != nil {
		return OperatorAccess{}, err
	}
	return s.operatorAccess(ctx, identity.ID)
}

func (s *Service) RevokeDelegations(
	ctx context.Context,
	actor Operator,
	operatorID string,
	customerID string,
	operations []Operation,
	reason string,
) (OperatorAccess, error) {
	if err := s.requireMutation(actor, true); err != nil {
		return OperatorAccess{}, err
	}
	if s.access == nil {
		return OperatorAccess{}, errors.New("provider: operator access store is not configured")
	}
	operatorID, customerID = strings.TrimSpace(operatorID), strings.TrimSpace(customerID)
	if operatorID == "" || customerID == "" {
		return OperatorAccess{}, errors.New("provider: operator_id and customer_id are required")
	}
	identity, err := s.access.ResolveOperator(ctx, operatorID)
	if err != nil {
		return OperatorAccess{}, err
	}
	operations, err = normalizeOperations(operations)
	if err != nil {
		return OperatorAccess{}, err
	}
	now := s.clock().UTC()
	delegations := make([]DelegationMutation, 0, len(operations))
	for _, operation := range operations {
		delegations = append(delegations, DelegationMutation{
			OperatorID: identity.ID, CustomerID: customerID, Operation: operation, Source: "console",
		})
	}
	if _, err := s.emit(ctx, EventDelegationRevoked, customerID, AuthorityEvent{
		Delegations: delegations, EffectiveAt: now,
		Audit: AuditEvent{Type: EventDelegationRevoked, TenantID: customerID,
			OperatorID: actor.ID, OperatorEmail: actor.Email, Subject: identity.ID,
			Reason: strings.TrimSpace(reason), At: now},
	}); err != nil {
		return OperatorAccess{}, err
	}
	return s.operatorAccess(ctx, identity.ID)
}

// SetOperatorRole changes the Provider privilege ceiling while preserving the
// IdP/SCIM identity source. OIDC/SAML still takes the LESSER of its signed role
// and this row on every request, so a console downgrade bites immediately and
// a console promotion cannot exceed what the IdP asserted.
func (s *Service) SetOperatorRole(ctx context.Context, actor Operator, operatorID string, role OperatorRole) (OperatorAccess, error) {
	if err := s.requireMutation(actor, true); err != nil {
		return OperatorAccess{}, err
	}
	if s.access == nil {
		return OperatorAccess{}, errors.New("provider: operator access store is not configured")
	}
	if !validOperatorRole(role) {
		return OperatorAccess{}, errors.New("provider: role must be admin or operator")
	}
	identity, err := s.access.ResolveOperator(ctx, strings.TrimSpace(operatorID))
	if err != nil {
		return OperatorAccess{}, err
	}
	if !identity.Active {
		return OperatorAccess{}, fmt.Errorf("%w: an inactive operator has no assignable role", ErrForbidden)
	}
	now := s.clock().UTC()
	identity.Role, identity.UpdatedAt = role, now
	if _, err := s.emit(ctx, EventOperatorUpserted, providerAuthorityTenant, AuthorityEvent{
		Operator: &identity, EffectiveAt: now,
		Audit: AuditEvent{Type: EventOperatorUpserted, TenantID: providerAuthorityTenant,
			OperatorID: actor.ID, OperatorEmail: actor.Email, Subject: identity.ID,
			Reason: "provider role changed to " + string(role), At: now},
	}); err != nil {
		return OperatorAccess{}, err
	}
	return s.operatorAccess(ctx, identity.ID)
}

func (s *Service) operatorAccess(ctx context.Context, operatorID string) (OperatorAccess, error) {
	rows, err := s.access.ListOperatorAccess(ctx)
	if err != nil {
		return OperatorAccess{}, err
	}
	for _, row := range rows {
		if row.Identity.ID == operatorID {
			return row, nil
		}
	}
	return OperatorAccess{}, ErrNotFound
}
