// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// memberAdmission checks both sides of a role replacement in the transaction
// that owns the durable member command. The target cannot change between this
// decision and the command claim.
func (a *API) memberAdmission(principal authz.Principal, newRoles []string, offboard bool) store.TenantMemberAdmission {
	return func(ctx context.Context, tx pgx.Tx, tenantID, subject string) error {
		scope := authz.Scope{TenantID: tenantID}
		if principal.Subject == subject {
			return errStatus(http.StatusForbidden, "self member authority changes are not allowed")
		}
		if !principal.Can(authz.AccessRoleAssign, scope) {
			return errStatus(http.StatusForbidden, "access:role.assign is required to change member authority")
		}
		if a.breakglassAdmin != nil && a.breakglassAdmin.IsAdminActor(tenantID, subject) {
			return errStatus(http.StatusForbidden, "the configured emergency administrator is managed outside tenant member administration")
		}
		oldRoles, status, exists, err := a.store.MemberAuthorityTx(ctx, tx, tenantID, subject)
		if err != nil {
			return err
		}
		admin := principal.Can(authz.Wildcard, scope)
		// A new member with explicit roles is bounded by those roles. An
		// existing empty role set, an unknown offboard target, or a new empty
		// role set may defer to external sign-in authority.
		if !admin && ((exists && len(oldRoles) == 0) || (!exists && (offboard || len(newRoles) == 0))) {
			return errStatus(http.StatusForbidden, "changing a member with unrecorded sign-in authority requires administrator authority")
		}
		oldWildcard, err := a.holdsMemberRolesTx(ctx, tx, tenantID, principal, oldRoles)
		if err != nil {
			return err
		}
		if !offboard {
			if len(newRoles) == 0 && !admin {
				return errStatus(http.StatusForbidden, "clearing member roles requires administrator authority because sign-in roles may apply")
			}
			newWildcard, err := a.holdsMemberRolesTx(ctx, tx, tenantID, principal, newRoles)
			if err != nil {
				return err
			}
			if status == "active" && oldWildcard && !newWildcard {
				return a.requireAnotherWildcardMemberTx(ctx, tx, tenantID)
			}
			return nil
		}
		if status == "active" && oldWildcard {
			return a.requireAnotherWildcardMemberTx(ctx, tx, tenantID)
		}
		return nil
	}
}

func (a *API) holdsMemberRolesTx(ctx context.Context, tx pgx.Tx, tenantID string, principal authz.Principal, names []string) (bool, error) {
	scope := authz.Scope{TenantID: tenantID}
	wildcard := false
	for _, name := range names {
		role, ok := a.roles.Role(name)
		if !ok {
			permissions, err := a.store.MemberCustomRolePermissionsTx(ctx, tx, tenantID, name)
			if errors.Is(err, pgx.ErrNoRows) {
				return false, errStatus(http.StatusForbidden, "member role is no longer defined")
			}
			if err != nil {
				return false, err
			}
			role = authz.Role{Name: name}
			for _, permission := range permissions {
				role.Permissions = append(role.Permissions, authz.Permission(permission))
			}
		}
		if role.Allows(authz.Wildcard) {
			wildcard = true
		}
		for _, permission := range role.Permissions {
			if !principal.Can(permission, scope) {
				return false, errStatus(http.StatusForbidden, "changing a member with broader authority requires that authority")
			}
		}
	}
	return wildcard, nil
}

func (a *API) requireAnotherWildcardMemberTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	var names, registered []string
	for _, role := range a.roles.Roles() {
		registered = append(registered, role.Name)
		if role.Allows(authz.Wildcard) {
			names = append(names, role.Name)
		}
	}
	count, err := a.store.MemberWildcardHolderCountTx(ctx, tx, tenantID, names, registered)
	if err != nil {
		return err
	}
	if count <= 1 {
		return errStatus(http.StatusForbidden, "the last administrator cannot lose member authority")
	}
	return nil
}
