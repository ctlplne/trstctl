// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/authz"
)

// Vault engine configuration paths over the configured providers (A203-L2).
// A stock Vault or OpenBao client, or a migration tool, lists and reads a
// dynamic engine's roles, and the database engine's connections, the way it
// reads them from Vault: {mount}/roles and {mount}/roles/{role} for the
// database, aws and kubernetes engines, and database/config and
// database/config/{name}, at the engine mount or at a provider's own mount.
// trstctl takes its providers and roles from its configuration file, never
// from these paths, so a write or delete answers 405 naming where the
// configuration lives. No DSN, key, token or other credential is in any
// response: a role names its provider, its lifetimes and, where the provider
// reports them, its namespace and audience.

const vaultEngineConfigReadOnlyDetail = "trstctl configures dynamic-secret providers and roles in its configuration file (dynamic_secrets.providers); this path is read-only"

var vaultCompatEngineConfigRoutes = []vaultCompatRoute{
	vaultEngineConfigRoute("LIST", "/v1/{mount}/roles", "/v1/{mount}/roles", "vaultCompatEngineRolesList", "/v1/database/roles",
		"List the roles a Vault database, AWS or Kubernetes engine offers", "VaultKVListResponse"),
	vaultEngineConfigRoute(http.MethodGet, "/v1/{mount}/roles", "/v1/{mount}/roles", "vaultCompatEngineRolesListGet", "/v1/database/roles?list=true",
		"List the roles a Vault database, AWS or Kubernetes engine offers (GET with ?list=true)", "VaultKVListResponse"),
	vaultEngineConfigRoute(http.MethodGet, "/v1/{mount}/roles/{name}", "/v1/{mount}/roles/{name}", "vaultCompatEngineRoleRead", "/v1/database/roles/readonly",
		"Read one engine role: the provider that serves it and its lease lifetimes", "VaultGenericResponse"),
	vaultEngineConfigRoute("LIST", "/v1/{mount}/config", "/v1/{mount}/config", "vaultCompatEngineConfigList", "/v1/database/config",
		"List the database engine's connections (the configured providers)", "VaultKVListResponse"),
	vaultEngineConfigRoute(http.MethodGet, "/v1/{mount}/config", "/v1/{mount}/config", "vaultCompatEngineConfigListGet", "/v1/database/config?list=true",
		"List the database engine's connections (GET with ?list=true)", "VaultKVListResponse"),
	vaultEngineConfigRoute(http.MethodGet, "/v1/{mount}/config/{name}", "/v1/{mount}/config/{name}", "vaultCompatEngineConfigRead", "/v1/database/config/pg-main",
		"Read one database connection: its plugin and the roles it allows, never its connection secret", "VaultGenericResponse"),
	vaultEngineConfigWriteRoute(http.MethodPost, "/v1/{mount}/roles/{name}", "vaultCompatEngineRoleWrite"),
	vaultEngineConfigWriteRoute(http.MethodPut, "/v1/{mount}/roles/{name}", "vaultCompatEngineRoleWritePut"),
	vaultEngineConfigWriteRoute(http.MethodDelete, "/v1/{mount}/roles/{name}", "vaultCompatEngineRoleDelete"),
	vaultEngineConfigWriteRoute(http.MethodPost, "/v1/{mount}/config/{name}", "vaultCompatEngineConfigWrite"),
	vaultEngineConfigWriteRoute(http.MethodPut, "/v1/{mount}/config/{name}", "vaultCompatEngineConfigWritePut"),
	vaultEngineConfigWriteRoute(http.MethodDelete, "/v1/{mount}/config/{name}", "vaultCompatEngineConfigDelete"),
}

func vaultEngineConfigRoute(method, pattern, contractPath, operationID, samplePath, summary, responseSchema string) vaultCompatRoute {
	return vaultCompatRoute{
		method: method, pattern: pattern, contractPath: contractPath, samplePath: samplePath,
		operationID: operationID, summary: summary, successCode: "200", permission: authz.SecretsRead,
		tokenRequired: true, responseSchema: responseSchema,
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultEngineConfig) },
	}
}

func vaultEngineConfigWriteRoute(method, pattern, operationID string) vaultCompatRoute {
	return vaultCompatRoute{
		method: method, pattern: pattern, contractPath: pattern, samplePath: strings.ReplaceAll(strings.ReplaceAll(pattern, "{mount}", "database"), "{name}", "readonly"),
		operationID: operationID, summary: "Refused (405) for a dynamic engine: trstctl configures providers and roles in its configuration file",
		successCode: "405", permission: authz.SecretsWrite, tokenRequired: true, mutation: true, responseSchema: "VaultGenericResponse",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultEngineConfig) },
	}
}

// vaultEngineConfigProviders is the providers a mount names: one provider
// at its own mount, or every provider of an engine at the engine mount.
// engine is empty when the mount is no dynamic engine of this tenant.
func (s *secretsService) vaultEngineConfigProviders(tenantID, mount string) (string, []dynamicSecretConfiguredProvider) {
	providers := s.configuredDynamicSecretProviders(tenantID)
	for _, provider := range providers {
		if provider.ID == mount {
			engine := vaultEngineForProviderType(provider.Type)
			if engine == "" {
				return "", nil
			}
			return engine, []dynamicSecretConfiguredProvider{provider}
		}
	}
	types, engine := vaultDynamicEngines[mount]
	if !engine {
		return "", nil
	}
	var offered []dynamicSecretConfiguredProvider
	for _, provider := range providers {
		if slices.Contains(types, provider.Type) {
			offered = append(offered, provider)
		}
	}
	if len(offered) == 0 {
		return "", nil
	}
	return mount, offered
}

// vaultEngineConfig serves the engine configuration paths. A mount that is
// not a dynamic engine of this tenant is the cubbyhole's, like any other
// /v1/{mount}/{path}.
func (a *API) vaultEngineConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	mount, name := r.PathValue("mount"), r.PathValue("name")
	kind := "roles"
	if strings.HasSuffix(r.URL.Path, "/config") || strings.Contains(r.URL.Path, "/config/") {
		kind = "config"
	}
	engine := ""
	var providers []dynamicSecretConfiguredProvider
	if a.secrets != nil {
		engine, providers = a.secrets.vaultEngineConfigProviders(tenantID, mount)
		// A235-L2: a provider in a restricted environment the caller is not
		// granted is not listed; a mount that names only such a provider is
		// no engine here.
		visible, err := a.visibleDynamicSecretProviders(r.Context(), tenantID, providers)
		if err != nil {
			writeVaultError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if len(visible) == 0 && len(providers) == 1 && providers[0].ID == mount {
			engine = ""
		}
		providers = visible
	}
	if engine == "" || (kind == "config" && engine != vaultDatabaseEngine) {
		a.vaultEngineConfigCubbyhole(w, r, kind, name)
		return
	}
	list := r.Method == "LIST" || (r.Method == http.MethodGet && name == "")
	switch {
	case r.Method != http.MethodGet && r.Method != "LIST":
		if !a.vaultAuthorizeOperation(w, r, authz.SecretsWrite) {
			return
		}
		writeVaultError(w, http.StatusMethodNotAllowed, vaultEngineConfigReadOnlyDetail)
		return
	case !a.vaultAuthorizeOperation(w, r, authz.SecretsRead):
		return
	case list && r.Method == http.MethodGet && r.URL.Query().Get("list") != "true":
		writeVaultError(w, http.StatusMethodNotAllowed, "list "+mount+"/"+kind+" with LIST or ?list=true")
		return
	case list:
		var keys []string
		for _, provider := range providers {
			if kind == "config" {
				keys = append(keys, provider.ID)
				continue
			}
			keys = append(keys, provider.AllowedRoles...)
		}
		sort.Strings(keys)
		keys = slices.Compact(keys)
		if len(keys) == 0 {
			writeVaultError(w, http.StatusNotFound, "")
			return
		}
		writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{"keys": keys}))
		return
	case kind == "config":
		for _, provider := range providers {
			if provider.ID == name {
				writeVaultJSON(w, http.StatusOK, newVaultEnvelope(vaultDatabaseConnection(provider)))
				return
			}
		}
		writeVaultError(w, http.StatusNotFound, "")
		return
	}
	var matches []dynamicSecretConfiguredProvider
	for _, provider := range providers {
		if slices.Contains(provider.AllowedRoles, name) {
			matches = append(matches, provider)
		}
	}
	switch len(matches) {
	case 0:
		writeVaultError(w, http.StatusNotFound, "")
		return
	case 1:
	default:
		ids := make([]string, 0, len(matches))
		for _, provider := range matches {
			ids = append(ids, provider.ID)
		}
		writeVaultError(w, http.StatusBadRequest, fmt.Sprintf("role %s is offered by providers %s; read it at <provider>/roles/%s", name, strings.Join(ids, ", "), name))
		return
	}
	scope, _ := a.secrets.vaultProviderScope(tenantID, matches[0].ID)
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(vaultEngineRole(engine, matches[0], scope)))
}

// vaultEngineConfigCubbyhole hands a path that is not a dynamic engine's to
// the cubbyhole, unchanged.
func (a *API) vaultEngineConfigCubbyhole(w http.ResponseWriter, r *http.Request, kind, name string) {
	path := kind
	if name != "" {
		path += "/" + name
	}
	r.SetPathValue("path", path)
	switch r.Method {
	case http.MethodGet:
		a.vaultCubbyholeReadOrList(w, r)
	case "LIST":
		a.vaultCubbyholeList(w, r)
	case http.MethodDelete:
		a.vaultCubbyholeDelete(w, r)
	default:
		a.vaultCubbyholeWrite(w, r)
	}
}

// vaultEngineRole lays one role out as the engine's Vault role data: the
// lifetimes in seconds and the provider that serves it, with no credential.
func vaultEngineRole(engine string, provider dynamicSecretConfiguredProvider, scope vaultDynamicProviderScope) map[string]any {
	maxTTL := provider.MaximumTTLSeconds
	defaultTTL := int64(vaultDefaultLeaseTTL.Seconds())
	if maxTTL > 0 && defaultTTL > maxTTL {
		defaultTTL = maxTTL
	}
	switch engine {
	case vaultAWSEngine:
		credentialType := "assumed_role"
		if provider.Type == "aws-iam" {
			credentialType = "iam_user"
		}
		return map[string]any{
			"credential_type": credentialType, "default_sts_ttl": defaultTTL, "max_sts_ttl": maxTTL,
			"trstctl_provider": provider.ID, "trstctl_provider_type": provider.Type,
		}
	case vaultKubernetesEngine:
		role := map[string]any{
			"token_default_ttl": defaultTTL, "token_max_ttl": maxTTL,
			"trstctl_provider": provider.ID, "trstctl_provider_type": provider.Type,
		}
		if scope != nil {
			if namespace, audience := scope.DynamicSecretKubernetesScope(); namespace != "" {
				role["allowed_kubernetes_namespaces"] = []string{namespace}
				if audience != "" {
					role["token_default_audiences"] = []string{audience}
				}
			}
		}
		return role
	default:
		return map[string]any{
			"db_name": provider.ID, "default_ttl": defaultTTL, "max_ttl": maxTTL, "credential_type": "password",
			"creation_statements": []string{}, "revocation_statements": []string{}, "renew_statements": []string{}, "rollback_statements": []string{},
			"trstctl_provider_type": provider.Type,
		}
	}
}

// vaultDatabaseConnection lays one provider out as a database engine
// connection: its plugin, the roles it allows and whether it is ready. The
// connection's DSN and credentials are never part of it.
func vaultDatabaseConnection(provider dynamicSecretConfiguredProvider) map[string]any {
	roles := append([]string(nil), provider.AllowedRoles...)
	sort.Strings(roles)
	return map[string]any{
		"plugin_name": provider.Type + "-database-plugin", "allowed_roles": roles,
		"connection_details": map[string]any{}, "verify_connection": provider.Ready,
		"password_policy": "", "root_credentials_rotate_statements": []string{},
		"trstctl_ready": provider.Ready, "trstctl_configuration_revision": provider.ConfigurationRevision,
	}
}
