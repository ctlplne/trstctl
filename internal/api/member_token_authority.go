// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// currentMemberTokenPrincipal applies a recorded member's current roles to
// its token scopes. Service subjects without a member record keep their
// token's explicitly granted scopes.
func (a *API) currentMemberTokenPrincipal(ctx context.Context, rec store.APITokenRecord) (authz.Principal, error) {
	token := auth.APIToken{TenantID: rec.TenantID, Subject: rec.Subject, Scopes: rec.Scopes, Delegated: rec.Delegated}.Principal()
	roles, status, found, pending, err := a.store.MemberSessionAuthority(ctx, rec.TenantID, rec.Subject)
	if err != nil {
		return authz.Principal{}, err
	}
	if pending || (found && status != "active") {
		return authz.Principal{}, errors.New("api: member authority unavailable")
	}
	if !found {
		return token, nil
	}
	resolved, err := a.resolveRoles(ctx, rec.TenantID, roles)
	if err != nil {
		return authz.Principal{}, err
	}
	member := authz.Principal{TenantID: rec.TenantID, Subject: rec.Subject}
	for _, name := range roles {
		if role, ok := resolved[name]; ok {
			member.Grants = append(member.Grants, authz.Grant{Role: role, Scope: authz.Scope{TenantID: rec.TenantID}})
		}
	}
	target := authz.Scope{TenantID: rec.TenantID}
	seen := map[authz.Permission]bool{}
	var effective []string
	add := func(permission authz.Permission) {
		if !seen[permission] && token.Can(permission, target) && member.Can(permission, target) {
			seen[permission] = true
			effective = append(effective, string(permission))
		}
	}
	for _, scope := range rec.Scopes {
		add(authz.Permission(scope))
	}
	for _, role := range resolved {
		for _, permission := range role.Permissions {
			add(permission)
		}
	}
	return auth.APIToken{TenantID: rec.TenantID, Subject: rec.Subject, Scopes: effective, Delegated: rec.Delegated}.Principal(), nil
}
