// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// The Vault/OpenBao shim's KV v2 metadata, folder listing and deletion paths,
// plus the two token paths stock tooling calls around them. They sit over the
// native application-secret store: metadata is the retained version history,
// a folder listing is the set of direct children of a name prefix, and a
// delete is the native delete (trstctl keeps no soft-deleted "deletion_time"
// state: a deleted object is gone from reads and listings, its history stays
// under native retention).

const vaultCompatListLimit = 10000

var vaultCompatKVExtraRoutes = []vaultCompatRoute{
	{
		method: http.MethodGet, pattern: "/v1/secret/metadata/{name...}", contractPath: "/v1/secret/metadata/{name}",
		samplePath: "/v1/secret/metadata/payments/db", operationID: "vaultCompatKVMetadataRead",
		summary:     "Read Vault KV v2 metadata (retained versions) for a served trstctl secret, or LIST a folder with ?list=true",
		successCode: "200", permission: authz.SecretsRead, tokenRequired: true, responseSchema: "VaultKVMetadataReadResponse",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsRead, a.vaultKVMetadataReadOrList) },
	},
	{
		method: "LIST", pattern: "/v1/secret/metadata/{name...}", contractPath: "/v1/secret/metadata/{name}",
		samplePath: "/v1/secret/metadata/payments", operationID: "vaultCompatKVList",
		summary:     "List the direct children of a Vault KV v2 folder in the served trstctl secret store",
		successCode: "200", permission: authz.SecretsRead, tokenRequired: true, responseSchema: "VaultKVListResponse",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsRead, a.vaultKVList) },
	},
	{
		method: http.MethodDelete, pattern: "/v1/secret/data/{name...}", contractPath: "/v1/secret/data/{name}",
		samplePath: "/v1/secret/data/payments/db", operationID: "vaultCompatKVDelete",
		summary:     "Delete a Vault KV v2 object from the served trstctl secret store (the native delete; no soft-delete state is kept)",
		successCode: "204", permission: authz.SecretsWrite, tokenRequired: true, mutation: true,
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultKVDelete) },
	},
	{
		method: http.MethodDelete, pattern: "/v1/secret/metadata/{name...}", contractPath: "/v1/secret/metadata/{name}",
		samplePath: "/v1/secret/metadata/payments/db", operationID: "vaultCompatKVMetadataDelete",
		summary:     "Delete a Vault KV v2 object and its metadata from the served trstctl secret store",
		successCode: "204", permission: authz.SecretsWrite, tokenRequired: true, mutation: true,
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultKVDelete) },
	},
	{
		method: http.MethodPost, pattern: "/v1/sys/capabilities-self", contractPath: "/v1/sys/capabilities-self",
		samplePath: "/v1/sys/capabilities-self", sampleBody: `{"paths":["secret/data/payments/db"]}`, operationID: "vaultCompatCapabilitiesSelf",
		summary:     "Report the Vault capabilities the presented token holds on each path, from its trstctl permissions and tenant ACL policies",
		successCode: "200", tokenRequired: true, requestSchema: "VaultCapabilitiesSelfRequest", responseSchema: "VaultCapabilitiesSelfResponse",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultCapabilitiesSelf) },
	},
	{
		method: http.MethodPost, pattern: "/v1/auth/token/renew-self", contractPath: "/v1/auth/token/renew-self",
		samplePath: "/v1/auth/token/renew-self", sampleBody: `{"increment":"1h"}`, operationID: "vaultCompatTokenRenewSelf",
		summary:     "Refused with Vault's own wording: trstctl API tokens are not renewable leases",
		successCode: "400", tokenRequired: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultErrorResponse",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultTokenRenewSelf) },
	},
}

func vaultCompatKVExtraSchemas(schemas map[string]*Schema) {
	anySchema := &Schema{}
	stringArray := &Schema{Type: "array", Items: str()}
	schemas["VaultKVVersionMetadata"] = object(map[string]*Schema{
		"created_time":  timestamp(),
		"deletion_time": str(),
		"destroyed":     {Type: "boolean"},
	}, "created_time", "deletion_time", "destroyed")
	schemas["VaultKVMetadataReadData"] = object(map[string]*Schema{
		"created_time":    timestamp(),
		"current_version": {Type: "integer"},
		"custom_metadata": object(map[string]*Schema{}),
		"max_versions":    {Type: "integer"},
		"oldest_version":  {Type: "integer"},
		"updated_time":    timestamp(),
		"versions":        object(map[string]*Schema{}),
	}, "created_time", "current_version", "max_versions", "oldest_version", "updated_time", "versions")
	schemas["VaultKVMetadataReadResponse"] = vaultCompatEnvelope("VaultKVMetadataReadData", anySchema)
	schemas["VaultKVListData"] = object(map[string]*Schema{"keys": stringArray}, "keys")
	schemas["VaultKVListResponse"] = vaultCompatEnvelope("VaultKVListData", anySchema)
	schemas["VaultCapabilitiesSelfRequest"] = object(map[string]*Schema{"paths": stringArray}, "paths")
	schemas["VaultCapabilitiesSelfData"] = object(map[string]*Schema{"capabilities": stringArray})
	schemas["VaultCapabilitiesSelfResponse"] = vaultCompatEnvelope("VaultCapabilitiesSelfData", anySchema)
}

func vaultKVName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := strings.Trim(r.PathValue("name"), "/")
	if name == "" {
		writeVaultError(w, http.StatusBadRequest, "secret path is required")
		return "", false
	}
	return name, true
}

func (a *API) vaultKVMetadataReadOrList(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("list") == "true" {
		a.vaultKVList(w, r)
		return
	}
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	name, ok := vaultKVName(w, r)
	if !ok {
		return
	}
	rec, err := a.secrets.be.Store.GetSecret(r.Context(), tenantID, name)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			writeVaultError(w, http.StatusNotFound, "no such secret")
			return
		}
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	versions := map[string]any{}
	oldest := 0
	for v := 1; v <= rec.Version; v++ {
		sv, err := a.secrets.be.Store.GetSecretVersion(r.Context(), tenantID, name, v)
		if err != nil {
			continue // a version outside native retention is not listed; it never existed from Vault's view
		}
		if oldest == 0 {
			oldest = v
		}
		versions[strconv.Itoa(v)] = map[string]any{
			"created_time": sv.WrittenAt.UTC().Format(time.RFC3339Nano), "deletion_time": "", "destroyed": false,
		}
	}
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
		"created_time":    rec.CreatedAt.UTC().Format(time.RFC3339Nano),
		"current_version": rec.Version,
		"custom_metadata": nil,
		"max_versions":    0,
		"oldest_version":  oldest,
		"updated_time":    rec.UpdatedAt.UTC().Format(time.RFC3339Nano),
		"versions":        versions,
	}))
}

// vaultKVList answers LIST secret/metadata/<folder>: the direct children of the
// folder, sub-folders suffixed with "/", sorted, and 404 for an empty folder as
// Vault does. The native store has no folders; a name's "/" segments are them.
func (a *API) vaultKVList(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	prefix := strings.Trim(r.PathValue("name"), "/")
	if prefix != "" {
		prefix += "/"
	}
	recs, err := a.secrets.be.Store.ListSecretNames(r.Context(), tenantID, vaultCompatListLimit)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	seen := map[string]bool{}
	for _, rec := range recs {
		if !strings.HasPrefix(rec.Name, prefix) {
			continue
		}
		rest := strings.TrimPrefix(rec.Name, prefix)
		if child, _, nested := strings.Cut(rest, "/"); nested {
			seen[child+"/"] = true
		} else if rest != "" {
			seen[rest] = true
		}
	}
	if len(seen) == 0 {
		writeVaultError(w, http.StatusNotFound, "no secrets under this path")
		return
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{"keys": keys}))
}

// vaultKVDelete runs the native delete for the named secret with the shim's
// token-keyed idempotency and reports the outcome in Vault's shape. Native
// problem documents never reach the Vault client.
func (a *API) vaultKVDelete(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	name, ok := vaultKVName(w, r)
	if !ok {
		return
	}
	key, ok := vaultStockCLIKey(w, r, nil)
	if !ok {
		return
	}
	native := r.Clone(r.Context())
	native.Header = r.Header.Clone()
	native.Header.Set("Idempotency-Key", key)
	native.SetPathValue("name", name)
	rec := httptest.NewRecorder()
	a.deleteSecret(rec, native)
	if rec.Code == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	detail := "delete failed"
	var problem struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &problem) == nil && strings.TrimSpace(problem.Detail) != "" {
		detail = problem.Detail
	}
	writeVaultError(w, rec.Code, detail)
}

type vaultCapabilitiesSelfRequest struct {
	Paths []string `json:"paths"`
	Path  string   `json:"path"`
}

// vaultCapabilitiesSelf maps a token's trstctl permissions onto Vault's
// capability words per path family the shim serves, then applies the tenant's
// Vault ACL policies the same way the request path would be gated. A path the
// token cannot touch at all reports ["deny"], as Vault does.
func (a *API) vaultCapabilitiesSelf(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.principalFor(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	var req vaultCapabilitiesSelfRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeVaultError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	paths := req.Paths
	if req.Path != "" {
		paths = append(paths, req.Path)
	}
	if len(paths) == 0 {
		writeVaultError(w, http.StatusBadRequest, "paths is required")
		return
	}
	scope := authz.Scope{TenantID: principal.TenantID, Project: r.Header.Get("X-Project")}
	data := map[string]any{}
	var first []string
	for _, raw := range paths {
		path := strings.Trim(strings.TrimSpace(raw), "/")
		caps := vaultPathCapabilities(path, func(perm authz.Permission) bool { return principal.Can(perm, scope) })
		granted := make([]string, 0, len(caps))
		for _, capability := range caps {
			allowed, governed, err := a.vaultACLDecision(r.Context(), principal.TenantID, principalRoles(principal), path, capability)
			if err != nil {
				writeVaultError(w, http.StatusInternalServerError, "ACL policy projection unavailable")
				return
			}
			if governed && !allowed {
				continue
			}
			granted = append(granted, capability)
		}
		if len(granted) == 0 {
			granted = []string{"deny"}
		}
		data[path] = granted
		if first == nil {
			first = granted
		}
	}
	data["capabilities"] = first
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(data))
}

// vaultPathCapabilities lists the Vault capabilities a path family grants for
// each trstctl permission the token holds; the order is Vault's conventional
// one. Unknown families grant nothing.
func vaultPathCapabilities(path string, can func(authz.Permission) bool) []string {
	var out []string
	add := func(perm authz.Permission, caps ...string) {
		if can(perm) {
			out = append(out, caps...)
		}
	}
	segments := strings.Split(path, "/")
	switch {
	case path == "auth/token/lookup-self" || path == "auth/token/renew-self" || path == "sys/capabilities-self" || path == "sys/health":
		return []string{"read", "update"}
	case strings.HasPrefix(path, "sys/policies/acl"):
		add(authz.PolicyRead, "read", "list")
		add(authz.PolicyWrite, "create", "update", "delete")
	case strings.HasPrefix(path, "sys/mounts") || strings.HasPrefix(path, "sys/internal/ui/mounts"):
		add(authz.PolicyRead, "read", "list")
		add(authz.PolicyWrite, "create", "update", "delete")
	case path == "secret" || strings.HasPrefix(path, "secret/") || (len(segments) >= 2 && (segments[1] == "data" || segments[1] == "metadata")):
		add(authz.SecretsRead, "read", "list")
		add(authz.SecretsWrite, "create", "update", "delete")
	case strings.HasPrefix(path, "pki/") || (len(segments) >= 2 && (segments[1] == "issue" || segments[1] == "sign")):
		add(authz.SecretsWrite, "create", "update")
	case len(segments) >= 2 && segments[1] == "verify":
		add(authz.KeysRead, "read", "update")
	case len(segments) >= 2 && (segments[1] == "keys" || segments[1] == "encrypt" || segments[1] == "decrypt" || segments[1] == "hmac" || segments[1] == "rewrap"):
		add(authz.KeysWrite, "create", "update")
	}
	return out
}

func (a *API) vaultTokenRenewSelf(w http.ResponseWriter, _ *http.Request) {
	writeVaultError(w, http.StatusBadRequest, "lease is not renewable: trstctl API tokens are not Vault leases; mint a new token instead")
}
