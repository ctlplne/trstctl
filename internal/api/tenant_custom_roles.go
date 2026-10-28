// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// A207: tenant custom roles. A role name resolves to the built-in (or
// deployment-configured) role of that name, else to the tenant's custom role,
// read per request so a changed or deleted role applies on every replica at
// once. A name that is neither grants nothing.

type tenantCustomRoleRequest struct {
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// resolveRoles returns the roles the names grant in the tenant.
func (a *API) resolveRoles(ctx context.Context, tenantID string, names []string) (map[string]authz.Role, error) {
	out := make(map[string]authz.Role, len(names))
	var custom []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if role, ok := a.roles.Role(name); ok {
			out[name] = role
		} else if name != "" {
			custom = append(custom, name)
		}
	}
	if len(custom) == 0 || a.store == nil || tenantID == "" {
		return out, nil
	}
	defined, err := a.store.ListTenantCustomRoles(ctx, tenantID, custom...)
	if err != nil {
		return nil, err
	}
	for _, role := range defined {
		perms := make([]authz.Permission, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			perms = append(perms, authz.Permission(p))
		}
		out[role.Name] = authz.Role{Name: role.Name, Permissions: perms}
	}
	return out, nil
}

// requireHeldPermissions refuses defining or assigning a role broader than the
// caller: every permission in it must be one the caller holds.
func requireHeldPermissions(ctx context.Context, tenantID string, perms []string, what string) error {
	principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok || principal.Subject == "" {
		return errStatus(http.StatusUnauthorized, "missing authenticated principal")
	}
	target := authz.Scope{TenantID: tenantID}
	for _, p := range perms {
		if !principal.Can(authz.Permission(p), target) {
			return errStatus(http.StatusForbidden, "cannot "+what+" a role with the permission "+p+" that you do not hold")
		}
	}
	return nil
}

func mapTenantCustomRoleError(err error) error {
	var invalid *orchestrator.InvalidTenantCustomRoleError
	switch {
	case errors.As(err, &invalid):
		return errStatus(http.StatusUnprocessableEntity, strings.TrimPrefix(invalid.Error(), "orchestrator: "))
	case errors.Is(err, orchestrator.ErrTenantCustomRoleHeld):
		return errStatus(http.StatusConflict, "members still hold this role; remove it from them first")
	case errors.Is(err, pgx.ErrNoRows):
		return errStatus(http.StatusNotFound, "custom role not found")
	}
	return err
}

//trstctl:mutation
func (a *API) defineTenantCustomRole(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "custom roles are not configured")
		}
		name := strings.TrimSpace(r.PathValue("name"))
		var req tenantCustomRoleRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := requireHeldPermissions(ctx, tenantID, req.Permissions, "define"); err != nil {
			return 0, nil, err
		}
		role, err := a.orch.DefineTenantCustomRole(ctx, tenantID, projections.TenantCustomRoleUpserted{
			Name: name, Description: strings.TrimSpace(req.Description), Permissions: req.Permissions,
		})
		if err != nil {
			return 0, nil, mapTenantCustomRoleError(err)
		}
		return http.StatusOK, roleResponse{Name: role.Name, Description: role.Description, Permissions: role.Permissions, Custom: true}, nil
	})
}

//trstctl:mutation
func (a *API) deleteTenantCustomRole(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "custom roles are not configured")
		}
		if err := a.orch.DeleteTenantCustomRole(ctx, tenantID, strings.TrimSpace(r.PathValue("name"))); err != nil {
			return 0, nil, mapTenantCustomRoleError(err)
		}
		return http.StatusNoContent, nil, nil
	})
}

// validateRoleNameShapes checks role names where no tenant is bound (a baseline
// document): each is a built-in or configured role, or a well-formed custom
// role name whose definition the tenant-bound apply step requires.
func (a *API) validateRoleNameShapes(roles []string) error {
	for _, name := range roles {
		if name == "" {
			return errStatus(http.StatusBadRequest, "role names must be non-empty")
		}
		if _, ok := a.roles.Role(name); ok {
			continue
		}
		if projections.ValidateTenantCustomRoleName(name) != nil {
			return errStatus(http.StatusUnprocessableEntity, "unknown role "+name)
		}
	}
	return nil
}
