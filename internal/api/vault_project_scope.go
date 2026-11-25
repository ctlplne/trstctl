// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"strings"

	"trstctl.com/trstctl/internal/authz"
)

// vaultTargetScope resolves the same backing secret name that the KV handler
// uses. A Vault path or a request header alone does not prove project membership:
// older tenant secrets can have the same path shape without belonging to a
// registered secrets project.
func (a *API) vaultTargetScope(ctx context.Context, principal authz.Principal, path string) (authz.Scope, error) {
	target := authz.Scope{TenantID: principal.TenantID}
	if a.store == nil {
		return target, nil
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || (parts[1] != "data" && parts[1] != "metadata") {
		return target, nil
	}
	name := strings.Join(parts[2:], "/")
	if parts[0] != vaultKVSecretMount {
		if parts[1] != "data" || a.vaultCompat == nil {
			return target, nil
		}
		state, err := a.vaultCompat.snapshot(ctx, principal.TenantID)
		if err != nil {
			return authz.Scope{}, err
		}
		mount, ok := state.mounts[parts[0]]
		if !ok || mount.Type != "kv" {
			return target, nil
		}
		name, err = vaultKVStoreNameForGeneration(mount, state.mountEpochs[parts[0]], name)
		if err != nil {
			return authz.Scope{}, err
		}
	}
	// A folder listing at <project>/<environment> targets that environment,
	// while SecretScopeFor normally expects a third, key-name segment.
	if parts[1] == "metadata" && strings.Count(name, "/") == 1 {
		name += "/_scope"
	}
	project, err := a.store.SecretScopeFor(ctx, principal.TenantID, name, principal.Subject)
	if err != nil {
		return authz.Scope{}, err
	}
	if project.InProject {
		target.Project = project.Project
	}
	return target, nil
}
