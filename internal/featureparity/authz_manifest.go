// SPDX-License-Identifier: BUSL-1.1

package featureparity

import "sort"

const (
	// APIFeatureAuthzTestRef is the table test that binds /api/v1 routes to
	// permission metadata and public-route rationales.
	APIFeatureAuthzTestRef = "internal/api/feature_authz_test.go"
)

// APIRouteAuthz is the authorization metadata exported by the served API route
// registry, normalized into feature-parity terms.
type APIRouteAuthz struct {
	OperationID     string
	Method          string
	Path            string
	Permission      string
	PublicRationale string
	OpenAPISecurity bool
}

// FeatureAuthzEntry binds one feature row to one served authorization surface.
// Exactly one of Permission or PublicRationale must be set: a route is either RBAC
// guarded by a named permission, or it is intentionally public because the
// protocol's own credential exchange authenticates the caller.
type FeatureAuthzEntry struct {
	FeatureID           string
	Feature             string
	Surface             string
	OperationID         string
	Method              string
	Path                string
	Permission          string
	PublicRationale     string
	DefaultDenyTest     string
	OpenAPISecurity     bool
	TenantMapping       string
	PrincipalMapping    string
	EnablementAuthority string
}

// BuildAPIFeatureAuthzManifest joins the feature catalog's api_surface entries to
// the live API route registry. The returned missing list names stale catalog
// operation IDs or routes that do not carry a permission/public rationale.
func BuildAPIFeatureAuthzManifest(catalog Catalog, routes []APIRouteAuthz) ([]FeatureAuthzEntry, []string) {
	byOp := make(map[string]APIRouteAuthz, len(routes))
	for _, r := range routes {
		if r.OperationID != "" {
			byOp[r.OperationID] = r
		}
	}

	var entries []FeatureAuthzEntry
	var missing []string
	for _, item := range catalog.Items {
		for _, opID := range item.APISurface {
			r, ok := byOp[opID]
			if !ok {
				missing = append(missing, item.FeatureID+":"+opID+" missing from served API route registry")
				continue
			}
			if r.Permission == "" && r.PublicRationale == "" {
				missing = append(missing, item.FeatureID+":"+opID+" has no permission or public rationale")
			}
			entries = append(entries, FeatureAuthzEntry{
				FeatureID:           item.FeatureID,
				Feature:             item.Feature,
				Surface:             "api",
				OperationID:         opID,
				Method:              r.Method,
				Path:                r.Path,
				Permission:          r.Permission,
				PublicRationale:     r.PublicRationale,
				DefaultDenyTest:     APIFeatureAuthzTestRef,
				OpenAPISecurity:     r.OpenAPISecurity,
				TenantMapping:       "guarded routes use the authenticated principal tenant; public credential-exchange routes bind tenant from the presented credential request.",
				PrincipalMapping:    "bearer API token, verified OIDC session, or the route-specific credential exchange for public login.",
				EnablementAuthority: "route registry permission metadata in internal/api/api.go",
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].FeatureID == entries[j].FeatureID {
			return entries[i].OperationID < entries[j].OperationID
		}
		return entries[i].FeatureID < entries[j].FeatureID
	})
	sort.Strings(missing)
	return entries, missing
}
