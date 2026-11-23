// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/credref"
)

// A235-L2: a stored-secret reference a caller sets up through the API — a
// connector target's config, a notification channel's or an observer's
// credential, a relay schedule's token, a DNS-01 provider's credentials, an
// MDM SCEP challenge key, an ACME EAB key, a discovery source's bind
// password, a secret sync's workload proof — is redeemed later by name with
// no request principal: by a network relay per attempt, a connector run, a
// notification send or a verifier. The request that sets the reference must
// hold secrets:read on the named secret and, for a restricted environment,
// membership in that environment. A background path with no authenticated
// tenant principal cannot create new secret references implicitly.

func storedSecretScopeName(ref string) (string, error) {
	if !credref.IsStored(ref) {
		return "", nil
	}
	parsed, err := credref.Parse(ref)
	if err != nil {
		return credref.NameForDenial(err), err
	}
	return parsed.Name, nil
}

// secretReferencesIn returns every secret:// reference string anywhere in a
// JSON document, walked the way the relay's collectSecretRefs walks a job
// payload, so a field added later cannot carry a reference this misses.
func secretReferencesIn(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if credref.IsStored(t) {
				out = append(out, t)
			}
		case map[string]any:
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(decoded)
	return out
}

// errSecretReferenceRestricted is the refusal: the reference names a secret
// in a restricted environment the caller is not granted. It says nothing
// about whether that secret exists.
func errSecretReferenceRestricted(field string) error {
	return errStatus(http.StatusForbidden, field+" names a secret in a restricted environment you are not granted: a reference is a read, so only that environment's members may set it")
}

func errSecretReferenceReadAuthority(field string) error {
	return errStatus(http.StatusForbidden, field+" requires secrets:read on the named secret")
}

// requireSecretReferencesRead refuses any stored reference the configuring
// principal could not read directly. A project-scoped read grant applies only
// when the named secret belongs to that project; an unrestricted name still
// needs secrets:read, and a missing principal fails closed.
func (a *API) requireSecretReferencesRead(ctx context.Context, tenantID, field string, refs ...string) error {
	for _, ref := range refs {
		name, formatErr := storedSecretScopeName(ref)
		if name != "" {
			principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
			if !ok || principal.Subject == "" || principal.TenantID != tenantID {
				return errSecretReferenceReadAuthority(field)
			}
			target := authz.Scope{TenantID: tenantID}
			if a.store != nil {
				scope, err := a.store.SecretScopeFor(ctx, tenantID, name, principal.Subject)
				if err != nil {
					return err
				}
				if scope.InProject {
					target.Project = scope.Project
					if scope.Restricted && !scope.CanRead {
						return errSecretReferenceRestricted(field)
					}
				}
			}
			if !principal.Can(authz.SecretsRead, target) {
				return errSecretReferenceReadAuthority(field)
			}
		}
		if formatErr != nil {
			return errStatus(http.StatusBadRequest, field+": "+formatErr.Error())
		}
	}
	return nil
}

// requireSecretReferencesReadIn applies requireSecretReferencesRead to every
// secret:// reference in a JSON document (a target's config, a reference
// object).
func (a *API) requireSecretReferencesReadIn(ctx context.Context, tenantID, field string, docs ...json.RawMessage) error {
	for _, doc := range docs {
		if err := a.requireSecretReferencesRead(ctx, tenantID, field, secretReferencesIn(doc)...); err != nil {
			return err
		}
	}
	return nil
}
