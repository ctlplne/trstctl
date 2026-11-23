// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/credref"
)

// requireCurrentSecretReferenceRead checks the recorded configurer immediately
// before a worker opens the secret. Losing a project membership, tenant role,
// or live token stops a previously configured notification destination from
// receiving a newer version. Rows without an event actor fail closed.
func (r integrationCredentialResolver) requireCurrentSecretReferenceRead(ctx context.Context, tenantID, ref, configuredBy string) error {
	if r.store == nil || strings.TrimSpace(configuredBy) == "" {
		return credref.ErrReadAuthorityRevoked
	}
	parsed, err := credref.Parse(ref)
	if err != nil {
		return credref.ErrReadAuthorityRevoked
	}
	scope, err := r.store.SecretScopeFor(ctx, tenantID, parsed.Name, configuredBy)
	if err != nil {
		return err
	}
	if scope.Restricted && !scope.CanRead {
		return credref.ErrReadAuthorityRevoked
	}
	held, err := r.store.GetSubjectStandingAuthority(ctx, tenantID, configuredBy, time.Now().UTC())
	if err != nil {
		return err
	}
	for _, permission := range held.TokenScopes {
		if (authz.Role{Permissions: []authz.Permission{authz.Permission(permission)}}).Allows(authz.SecretsRead) {
			return nil
		}
	}
	builtin := authz.BuiltinRoles()
	var custom []string
	for _, name := range held.MemberRoles {
		if role, ok := builtin[name]; ok {
			if role.Allows(authz.SecretsRead) {
				return nil
			}
		} else if name != "" {
			custom = append(custom, name)
		}
	}
	if len(custom) > 0 {
		roles, err := r.store.ListTenantCustomRoles(ctx, tenantID, custom...)
		if err != nil {
			return err
		}
		for _, role := range roles {
			for _, permission := range role.Permissions {
				if (authz.Role{Permissions: []authz.Permission{authz.Permission(permission)}}).Allows(authz.SecretsRead) {
					return nil
				}
			}
		}
	}
	return credref.ErrReadAuthorityRevoked
}
