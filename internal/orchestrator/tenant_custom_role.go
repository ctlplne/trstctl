// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A207: tenant custom roles.

// ErrTenantCustomRoleHeld refuses deleting a role a member still holds.
var ErrTenantCustomRoleHeld = errors.New("orchestrator: members still hold that role")

// InvalidTenantCustomRoleError is a definition the projection would refuse.
type InvalidTenantCustomRoleError struct{ Reason string }

func (e *InvalidTenantCustomRoleError) Error() string { return "orchestrator: " + e.Reason }

// DefineTenantCustomRole records a custom role definition and returns the role
// as projected.
func (o *Orchestrator) DefineTenantCustomRole(ctx context.Context, tenantID string, def projections.TenantCustomRoleUpserted) (store.TenantCustomRole, error) {
	if err := projections.ValidateTenantCustomRole(def); err != nil {
		return store.TenantCustomRole{}, &InvalidTenantCustomRoleError{Reason: err.Error()}
	}
	data, err := json.Marshal(def)
	if err != nil {
		return store.TenantCustomRole{}, err
	}
	if _, err := o.emit(ctx, projections.EventTenantCustomRoleUpserted, tenantID, data); err != nil {
		return store.TenantCustomRole{}, err
	}
	return o.store.GetTenantCustomRole(ctx, tenantID, def.Name)
}

// DeleteTenantCustomRole deletes a custom role no member holds. A member who
// gains the role in a race keeps only a name that grants nothing: role
// resolution ignores names that are neither built in nor defined.
func (o *Orchestrator) DeleteTenantCustomRole(ctx context.Context, tenantID, name string) error {
	if err := projections.ValidateTenantCustomRoleName(name); err != nil {
		return &InvalidTenantCustomRoleError{Reason: err.Error()}
	}
	if _, err := o.store.GetTenantCustomRole(ctx, tenantID, name); err != nil {
		return err
	}
	holders, err := o.store.TenantCustomRoleHolders(ctx, tenantID, name)
	if err != nil {
		return err
	}
	if holders > 0 {
		return ErrTenantCustomRoleHeld
	}
	data, err := json.Marshal(projections.TenantCustomRoleDeleted{Name: name})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventTenantCustomRoleDeleted, tenantID, data)
	return err
}
