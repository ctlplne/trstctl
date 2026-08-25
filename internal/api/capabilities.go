// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"sort"
	"sync"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/featureparity"
)

const capabilityViewSchemaVersion = 1

var (
	runtimeCapabilityCatalogOnce sync.Once
	runtimeCapabilityCatalog     featureparity.Catalog
	runtimeCapabilityCatalogErr  error
)

type capabilityLicensePosture struct {
	Tier  string `json:"tier"`
	State string `json:"state"`
}

type capabilityViewStage struct {
	Name       string                    `json:"name"`
	Completion featureparity.StageStatus `json:"completion"`
	Reason     string                    `json:"reason,omitempty"`
}

type capabilityUnavailableAction struct {
	OperationID string `json:"operation_id"`
	Code        string `json:"code"`
	Detail      string `json:"detail"`
}

type capabilityViewActions struct {
	Allowed     []string                      `json:"allowed"`
	Scoped      []string                      `json:"scoped"`
	Denied      []string                      `json:"denied"`
	Unavailable []capabilityUnavailableAction `json:"unavailable"`
}

type capabilityViewItem struct {
	CapabilityID       string                                 `json:"capability_id"`
	Name               string                                 `json:"name"`
	Purpose            string                                 `json:"purpose"`
	Tool               featureparity.CanonicalTool            `json:"tool"`
	Classification     featureparity.CapabilityClassification `json:"classification"`
	ConsoleRoute       string                                 `json:"console_route"`
	Maturity           featureparity.Maturity                 `json:"maturity"`
	ReleaseBlocking    bool                                   `json:"release_blocking"`
	Edition            string                                 `json:"edition"`
	RuntimeState       string                                 `json:"runtime_state"`
	AuthorizationState string                                 `json:"authorization_state"`
	DependencyState    string                                 `json:"dependency_state"`
	Dependencies       []string                               `json:"dependencies"`
	Stages             []capabilityViewStage                  `json:"stages"`
	Actions            capabilityViewActions                  `json:"actions"`
}

type capabilityViewResponse struct {
	SchemaVersion         int                      `json:"schema_version"`
	ContractSchemaVersion int                      `json:"contract_schema_version"`
	License               capabilityLicensePosture `json:"license"`
	EnforcementNote       string                   `json:"enforcement_note"`
	Items                 []capabilityViewItem     `json:"items"`
}

type capabilityRouteState struct {
	route   route
	enabled bool
}

func loadRuntimeCapabilityCatalog() (featureparity.Catalog, error) {
	runtimeCapabilityCatalogOnce.Do(func() {
		runtimeCapabilityCatalog, runtimeCapabilityCatalogErr = featureparity.LoadEmbedded()
	})
	return runtimeCapabilityCatalog, runtimeCapabilityCatalogErr
}

// listCapabilities projects the canonical product contract through the exact
// routes and RBAC grants in this process. It intentionally omits source paths,
// evidence, candidate SHAs, owner names, and secret-handling implementation
// details. The browser learns what is useful; engineering internals stay in QA.
func (a *API) listCapabilities(w http.ResponseWriter, r *http.Request) {
	catalog, err := loadRuntimeCapabilityCatalog()
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "capability catalog unavailable"))
		return
	}
	principal, ok := r.Context().Value(principalCtxKey).(authz.Principal)
	if !ok || principal.TenantID == "" {
		a.writeError(w, errStatus(http.StatusUnauthorized, "authenticated capability reader is missing"))
		return
	}

	routes := make(map[string]capabilityRouteState)
	for _, rt := range a.routes() {
		if rt.opID == "" {
			continue
		}
		routes[rt.opID] = capabilityRouteState{route: rt, enabled: a.routeEnabled(rt)}
	}

	info := a.licenseManager().Info()
	response := capabilityViewResponse{
		SchemaVersion:         capabilityViewSchemaVersion,
		ContractSchemaVersion: catalog.SchemaVersion,
		License:               capabilityLicensePosture{Tier: string(info.Tier), State: string(info.State)},
		EnforcementNote:       "This is a route and RBAC preflight, not a bypass. Resource scope, ABAC policy, tenant key state, mutation gates, idempotency, and live dependencies are checked again when an action runs.",
		Items:                 make([]capabilityViewItem, 0, len(catalog.Items)),
	}
	for _, item := range catalog.Items {
		response.Items = append(response.Items, a.projectCapability(item, principal, routes))
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) projectCapability(item featureparity.Item, principal authz.Principal, routes map[string]capabilityRouteState) capabilityViewItem {
	contract := item.Contract
	out := capabilityViewItem{
		CapabilityID:    item.FeatureID,
		Name:            item.Feature,
		Purpose:         contract.Purpose,
		Tool:            contract.Tool,
		Classification:  contract.Classification,
		ConsoleRoute:    contract.ConsoleRoute,
		Maturity:        featureparity.ComputeMaturity(contract.Stages),
		ReleaseBlocking: contract.ReleaseBlocking,
		Edition:         contract.Edition,
		DependencyState: "none",
		Dependencies:    append([]string(nil), contract.Dependencies...),
		Stages:          sanitizedCapabilityStages(contract.Stages),
		Actions: capabilityViewActions{
			Allowed:     []string{},
			Scoped:      []string{},
			Denied:      []string{},
			Unavailable: []capabilityUnavailableAction{},
		},
	}
	if len(out.Dependencies) > 0 {
		out.DependencyState = "documented_not_runtime_verified"
	}

	availableRoutes := 0
	for _, operationID := range item.APISurface {
		state, exists := routes[operationID]
		if !exists {
			out.Actions.Unavailable = append(out.Actions.Unavailable, capabilityUnavailableAction{
				OperationID: operationID,
				Code:        "not_attached",
				Detail:      "This operation is not attached to the running control-plane process.",
			})
			continue
		}
		if state.route.unavailableReason != "" {
			out.Actions.Unavailable = append(out.Actions.Unavailable, capabilityUnavailableAction{
				OperationID: operationID,
				Code:        "not_implemented",
				Detail:      state.route.unavailableReason,
			})
			continue
		}
		if !state.enabled {
			out.Actions.Unavailable = append(out.Actions.Unavailable, capabilityUnavailableAction{
				OperationID: operationID,
				Code:        "dependency_not_configured",
				Detail:      "This operation is not mounted because its runtime dependency is not configured.",
			})
			continue
		}
		availableRoutes++
		switch capabilityOperationAccess(principal, state.route) {
		case "allowed":
			out.Actions.Allowed = append(out.Actions.Allowed, operationID)
		case "scoped":
			out.Actions.Scoped = append(out.Actions.Scoped, operationID)
		default:
			out.Actions.Denied = append(out.Actions.Denied, operationID)
		}
	}
	sort.Strings(out.Actions.Allowed)
	sort.Strings(out.Actions.Scoped)
	sort.Strings(out.Actions.Denied)
	sort.Slice(out.Actions.Unavailable, func(i, j int) bool {
		return out.Actions.Unavailable[i].OperationID < out.Actions.Unavailable[j].OperationID
	})

	out.RuntimeState = capabilityRuntimeState(len(item.APISurface), availableRoutes)
	out.AuthorizationState = capabilityAuthorizationState(len(item.APISurface), out.Actions)
	return out
}

func capabilityOperationAccess(principal authz.Principal, rt route) string {
	if rt.perm == "" {
		return "allowed"
	}
	tenantWide := authz.Scope{TenantID: principal.TenantID}
	if principal.Can(rt.perm, tenantWide) {
		return "allowed"
	}
	// A narrowed grant can be useful only when the route derives an exact target
	// scope. Tenant-wide list routes correctly remain denied.
	if rt.scope != nil {
		for _, grant := range principal.Grants {
			if grant.Scope.TenantID == principal.TenantID && grant.Role.Allows(rt.perm) {
				return "scoped"
			}
		}
	}
	return "denied"
}

func capabilityRuntimeState(total, available int) string {
	switch {
	case total == 0:
		return "catalog_only"
	case available == 0:
		return "unavailable"
	case available < total:
		return "partially_available"
	default:
		return "available"
	}
}

func capabilityAuthorizationState(total int, actions capabilityViewActions) string {
	if total == 0 {
		return "catalog_only"
	}
	permitted := len(actions.Allowed) + len(actions.Scoped)
	switch {
	case permitted == 0:
		return "none"
	case len(actions.Denied) == 0 && len(actions.Unavailable) == 0 && len(actions.Scoped) == 0:
		return "full"
	case len(actions.Denied) == 0 && len(actions.Unavailable) == 0 && len(actions.Allowed) == 0:
		return "scoped"
	default:
		return "partial"
	}
}

func sanitizedCapabilityStages(stages featureparity.StageSet) []capabilityViewStage {
	ordered := []struct {
		name  string
		stage featureparity.StageRecord
	}{
		{"discover", stages.Discover}, {"understand", stages.Understand},
		{"configure", stages.Configure}, {"preview", stages.Preview},
		{"execute", stages.Execute}, {"observe", stages.Observe},
		{"recover", stages.Recover}, {"verify", stages.Verify},
		{"automate", stages.Automate},
	}
	out := make([]capabilityViewStage, 0, len(ordered))
	for _, entry := range ordered {
		out = append(out, capabilityViewStage{Name: entry.name, Completion: entry.stage.Status, Reason: entry.stage.Reason})
	}
	return out
}
