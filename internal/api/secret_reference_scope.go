// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// A235-L2: a stored-secret reference a caller sets up through the API — a
// connector target's config, a notification channel's or an observer's
// credential, a relay schedule's token, a DNS-01 provider's credentials, an
// MDM SCEP challenge key, an ACME EAB key, a discovery source's bind
// password, a secret sync's workload proof — is redeemed later by name with
// no request principal: by a network relay per attempt, a connector run, a
// notification send or a verifier. So the request that sets the reference up
// is where a restricted environment is checked, as for a read: a caller
// cannot have trstctl send or use a secret it could not read itself. A
// reference to a secret outside every restricted environment stays governed
// by the route's own permission.

// storedSecretRefNames returns the stored secret names a secret:// reference
// resolves to, as each redeemer reads it: the integration form (the rest of
// the reference, trimmed of slashes) and the connector and relay form (the
// URL host and path, unescaped, with an optional ?version=N). Both are
// checked, so no spelling reaches a restricted secret through one redeemer
// while passing for another. A value that is not a secret:// reference
// names nothing.
func storedSecretRefNames(ref string) []string {
	ref = strings.TrimSpace(ref)
	rest, ok := strings.CutPrefix(ref, "secret://")
	if !ok {
		return nil
	}
	var names []string
	if raw := strings.Trim(strings.TrimSpace(rest), "/"); raw != "" {
		names = append(names, raw)
	}
	if parsed, err := url.Parse(ref); err == nil {
		escaped := strings.Trim(strings.TrimSpace(parsed.Host+parsed.EscapedPath()), "/")
		if name, err := url.PathUnescape(escaped); err == nil {
			name = strings.Trim(name, "/")
			if name != "" && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
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
			if strings.HasPrefix(strings.TrimSpace(t), "secret://") {
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

// requireSecretReferencesRead refuses any of refs (the request's field) that
// names a secret in a restricted environment the caller may not read.
func (a *API) requireSecretReferencesRead(ctx context.Context, tenantID, field string, refs ...string) error {
	for _, ref := range refs {
		for _, name := range storedSecretRefNames(ref) {
			ok, err := a.secretScopeAllows(ctx, tenantID, name, false)
			if err != nil {
				return err
			}
			if !ok {
				return errSecretReferenceRestricted(field)
			}
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
