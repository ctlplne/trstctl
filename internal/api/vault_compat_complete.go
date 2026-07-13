// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/transit"
)

var vaultCompatCompleteRoutes = []vaultCompatRoute{
	{method: http.MethodGet, pattern: "/v1/sys/mounts", contractPath: "/v1/sys/mounts", samplePath: "/v1/sys/mounts", operationID: "vaultCompatListMounts", summary: "List tenant Vault-compatible secret-engine mounts", successCode: "200", permission: authz.PolicyRead, tokenRequired: true, responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyRead, a.vaultListMounts) }},
	{method: http.MethodPost, pattern: "/v1/sys/mounts/{path...}", contractPath: "/v1/sys/mounts/{path}", samplePath: "/v1/sys/mounts/application-secrets", sampleBody: `{"type":"kv","options":{"version":"2"}}`, operationID: "vaultCompatEnableMount", summary: "Enable a tenant Vault-compatible KV v2, PKI, or transit mount", successCode: "204", permission: authz.PolicyWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyWrite, a.vaultEnableMount) }},
	{method: http.MethodPut, pattern: "/v1/sys/mounts/{path...}", contractPath: "/v1/sys/mounts/{path}", samplePath: "/v1/sys/mounts/application-secrets", sampleBody: `{"type":"kv","options":{"version":"2"}}`, operationID: "vaultCompatEnableMountPut", summary: "Enable a tenant Vault-compatible KV v2, PKI, or transit mount", successCode: "204", permission: authz.PolicyWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyWrite, a.vaultEnableMount) }},
	{method: http.MethodDelete, pattern: "/v1/sys/mounts/{path...}", contractPath: "/v1/sys/mounts/{path}", samplePath: "/v1/sys/mounts/application-secrets", operationID: "vaultCompatDisableMount", summary: "Disable a tenant Vault-compatible mount", successCode: "204", permission: authz.PolicyWrite, tokenRequired: true, mutation: true, responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyWrite, a.vaultDisableMount) }},
	{method: http.MethodGet, pattern: "/v1/sys/policies/acl", contractPath: "/v1/sys/policies/acl", samplePath: "/v1/sys/policies/acl", operationID: "vaultCompatListACLPolicies", summary: "List tenant Vault-compatible ACL policies", successCode: "200", permission: authz.PolicyRead, tokenRequired: true, responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyRead, a.vaultListPolicies) }},
	{method: http.MethodGet, pattern: "/v1/sys/policies/acl/{name}", contractPath: "/v1/sys/policies/acl/{name}", samplePath: "/v1/sys/policies/acl/operator", operationID: "vaultCompatReadACLPolicy", summary: "Read a tenant Vault-compatible ACL policy", successCode: "200", permission: authz.PolicyRead, tokenRequired: true, responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyRead, a.vaultReadPolicy) }},
	{method: http.MethodPost, pattern: "/v1/sys/policies/acl/{name}", contractPath: "/v1/sys/policies/acl/{name}", samplePath: "/v1/sys/policies/acl/operator", sampleBody: `{"policy":"path \"secret/data/*\" { capabilities = [\"read\"] }"}`, operationID: "vaultCompatPutACLPolicy", summary: "Author a tenant Vault-compatible ACL policy", successCode: "204", permission: authz.PolicyWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyWrite, a.vaultPutPolicy) }},
	{method: http.MethodPut, pattern: "/v1/sys/policies/acl/{name}", contractPath: "/v1/sys/policies/acl/{name}", samplePath: "/v1/sys/policies/acl/operator", sampleBody: `{"policy":"path \"secret/data/*\" { capabilities = [\"read\"] }"}`, operationID: "vaultCompatPutACLPolicyPut", summary: "Author a tenant Vault-compatible ACL policy", successCode: "204", permission: authz.PolicyWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyWrite, a.vaultPutPolicy) }},
	{method: http.MethodDelete, pattern: "/v1/sys/policies/acl/{name}", contractPath: "/v1/sys/policies/acl/{name}", samplePath: "/v1/sys/policies/acl/operator", operationID: "vaultCompatDeleteACLPolicy", summary: "Delete a tenant Vault-compatible ACL policy", successCode: "204", permission: authz.PolicyWrite, tokenRequired: true, mutation: true, responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.PolicyWrite, a.vaultDeletePolicy) }},
	{method: http.MethodGet, pattern: "/v1/{mount}/data/{name...}", contractPath: "/v1/{mount}/data/{name}", samplePath: "/v1/application-secrets/data/payments/db", operationID: "vaultCompatMountedKVRead", summary: "Read KV v2 data through a tenant-authored mount", successCode: "200", permission: authz.SecretsRead, tokenRequired: true, responseSchema: "VaultKVReadResponse", sensitiveResponse: true, handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsRead, a.vaultMountedKVRead) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/data/{name...}", contractPath: "/v1/{mount}/data/{name}", samplePath: "/v1/application-secrets/data/payments/db", sampleBody: `{"data":{"username":"payments"}}`, operationID: "vaultCompatMountedKVWrite", summary: "Write KV v2 data through a tenant-authored mount", successCode: "200", permission: authz.SecretsWrite, tokenRequired: true, mutation: true, requestSchema: "VaultKVWriteRequest", responseSchema: "VaultKVWriteResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultMountedKVWrite) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/data/{name...}", contractPath: "/v1/{mount}/data/{name}", samplePath: "/v1/application-secrets/data/payments/db", sampleBody: `{"data":{"username":"payments"}}`, operationID: "vaultCompatMountedKVWritePut", summary: "Write KV v2 data through a tenant-authored mount", successCode: "200", permission: authz.SecretsWrite, tokenRequired: true, mutation: true, requestSchema: "VaultKVWriteRequest", responseSchema: "VaultKVWriteResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultMountedKVWrite) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/issue/{role}", contractPath: "/v1/{mount}/issue/{role}", samplePath: "/v1/application-pki/issue/default", sampleBody: `{"common_name":"svc.example.test","ttl":"1h"}`, operationID: "vaultCompatMountedPKIIssue", summary: "Issue PKI material through a tenant-authored mount", successCode: "200", permission: authz.SecretsWrite, tokenRequired: true, mutation: true, requestSchema: "VaultPKIIssueRequest", responseSchema: "VaultPKIIssueResponse", sensitiveResponse: true, handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultMountedPKIIssue) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/issue/{role}", contractPath: "/v1/{mount}/issue/{role}", samplePath: "/v1/application-pki/issue/default", sampleBody: `{"common_name":"svc.example.test","ttl":"1h"}`, operationID: "vaultCompatMountedPKIIssuePut", summary: "Issue PKI material through a tenant-authored mount", successCode: "200", permission: authz.SecretsWrite, tokenRequired: true, mutation: true, requestSchema: "VaultPKIIssueRequest", responseSchema: "VaultPKIIssueResponse", sensitiveResponse: true, handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultMountedPKIIssue) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/keys/{name}", contractPath: "/v1/{mount}/keys/{name}", samplePath: "/v1/transit/keys/app", sampleBody: `{"type":"aes256-gcm96"}`, operationID: "vaultCompatTransitCreateKey", summary: "Create a Vault-compatible transit key", successCode: "204", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitCreateKey) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/keys/{name}", contractPath: "/v1/{mount}/keys/{name}", samplePath: "/v1/transit/keys/app", sampleBody: `{"type":"aes256-gcm96"}`, operationID: "vaultCompatTransitCreateKeyPut", summary: "Create a Vault-compatible transit key", successCode: "204", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitCreateKey) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/keys/{name}/rotate", contractPath: "/v1/{mount}/keys/{name}/rotate", samplePath: "/v1/transit/keys/app/rotate", sampleBody: `{}`, operationID: "vaultCompatTransitRotateKey", summary: "Rotate a Vault-compatible transit key", successCode: "204", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitRotateKey) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/encrypt/{name}", contractPath: "/v1/{mount}/encrypt/{name}", samplePath: "/v1/transit/encrypt/app", sampleBody: `{"plaintext":"cGF5bG9hZA=="}`, operationID: "vaultCompatTransitEncrypt", summary: "Encrypt with a Vault-compatible transit key", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitEncrypt) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/encrypt/{name}", contractPath: "/v1/{mount}/encrypt/{name}", samplePath: "/v1/transit/encrypt/app", sampleBody: `{"plaintext":"cGF5bG9hZA=="}`, operationID: "vaultCompatTransitEncryptPut", summary: "Encrypt with a Vault-compatible transit key", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitEncrypt) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/decrypt/{name}", contractPath: "/v1/{mount}/decrypt/{name}", samplePath: "/v1/transit/decrypt/app", sampleBody: `{"ciphertext":"vault:v1:opaque"}`, operationID: "vaultCompatTransitDecrypt", summary: "Decrypt with a Vault-compatible transit key", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", sensitiveResponse: true, handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitDecrypt) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/decrypt/{name}", contractPath: "/v1/{mount}/decrypt/{name}", samplePath: "/v1/transit/decrypt/app", sampleBody: `{"ciphertext":"vault:v1:opaque"}`, operationID: "vaultCompatTransitDecryptPut", summary: "Decrypt with a Vault-compatible transit key", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", sensitiveResponse: true, handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitDecrypt) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/rewrap/{name}", contractPath: "/v1/{mount}/rewrap/{name}", samplePath: "/v1/transit/rewrap/app", sampleBody: `{"ciphertext":"vault:v1:opaque"}`, operationID: "vaultCompatTransitRewrap", summary: "Rewrap a Vault-compatible transit ciphertext", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitRewrap) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/rewrap/{name}", contractPath: "/v1/{mount}/rewrap/{name}", samplePath: "/v1/transit/rewrap/app", sampleBody: `{"ciphertext":"vault:v1:opaque"}`, operationID: "vaultCompatTransitRewrapPut", summary: "Rewrap a Vault-compatible transit ciphertext", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitRewrap) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/hmac/{name}", contractPath: "/v1/{mount}/hmac/{name}", samplePath: "/v1/transit/hmac/app", sampleBody: `{"input":"cGF5bG9hZA=="}`, operationID: "vaultCompatTransitHMAC", summary: "Compute a Vault-compatible transit HMAC", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitHMAC) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/hmac/{name}", contractPath: "/v1/{mount}/hmac/{name}", samplePath: "/v1/transit/hmac/app", sampleBody: `{"input":"cGF5bG9hZA=="}`, operationID: "vaultCompatTransitHMACPut", summary: "Compute a Vault-compatible transit HMAC", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitHMAC) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/sign/{name}", contractPath: "/v1/{mount}/sign/{name}", samplePath: "/v1/transit/sign/app", sampleBody: `{"input":"cGF5bG9hZA=="}`, operationID: "vaultCompatTransitSign", summary: "Sign with a Vault-compatible transit key", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitSign) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/sign/{name}", contractPath: "/v1/{mount}/sign/{name}", samplePath: "/v1/transit/sign/app", sampleBody: `{"input":"cGF5bG9hZA=="}`, operationID: "vaultCompatTransitSignPut", summary: "Sign with a Vault-compatible transit key", successCode: "200", permission: authz.KeysWrite, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysWrite, a.vaultTransitSign) }},
	{method: http.MethodPost, pattern: "/v1/{mount}/verify/{name}", contractPath: "/v1/{mount}/verify/{name}", samplePath: "/v1/transit/verify/app", sampleBody: `{"input":"cGF5bG9hZA==","signature":"vault:v1:opaque"}`, operationID: "vaultCompatTransitVerify", summary: "Verify a Vault-compatible transit signature", successCode: "200", permission: authz.KeysRead, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysRead, a.vaultTransitVerify) }},
	{method: http.MethodPut, pattern: "/v1/{mount}/verify/{name}", contractPath: "/v1/{mount}/verify/{name}", samplePath: "/v1/transit/verify/app", sampleBody: `{"input":"cGF5bG9hZA==","signature":"vault:v1:opaque"}`, operationID: "vaultCompatTransitVerifyPut", summary: "Verify a Vault-compatible transit signature", successCode: "200", permission: authz.KeysRead, tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultGenericResponse", handler: func(a *API) http.HandlerFunc { return a.vaultAuth(authz.KeysRead, a.vaultTransitVerify) }},
}

func allVaultCompatRoutes() []vaultCompatRoute {
	out := make([]vaultCompatRoute, 0, len(vaultCompatRoutes)+len(vaultCompatCompleteRoutes))
	out = append(out, vaultCompatRoutes...)
	out = append(out, vaultCompatCompleteRoutes...)
	return out
}

func (a *API) mountVaultTransitRoutes(mux *http.ServeMux) {
	mux.HandleFunc("LIST /v1/sys/policies/acl", a.vaultAuth(authz.PolicyRead, a.vaultListPolicies))
}

type vaultMountRequest struct {
	Type                  string            `json:"type"`
	Description           string            `json:"description,omitempty"`
	Options               map[string]string `json:"options,omitempty"`
	Config                map[string]any    `json:"config,omitempty"`
	Local                 bool              `json:"local,omitempty"`
	SealWrap              bool              `json:"seal_wrap,omitempty"`
	ExternalEntropyAccess bool              `json:"external_entropy_access,omitempty"`
	PluginName            string            `json:"plugin_name,omitempty"`
}

func (a *API) vaultListMounts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	state, err := a.vaultCompat.snapshot(r.Context(), tenantID)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "mount projection unavailable")
		return
	}
	mounts := a.vaultBuiltinMounts()
	for path, mount := range state.mounts {
		mounts[path+"/"] = vaultMountResponse(mount)
	}
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(mounts))
}

func (a *API) vaultBuiltinMounts() map[string]any {
	mounts := map[string]any{
		"secret/": vaultMountResponse(vaultCompatMount{Path: "secret", Type: "kv", Description: "trstctl sealed secret store", Options: map[string]string{"version": "2"}}),
	}
	if a.secrets != nil {
		mounts["pki/"] = vaultMountResponse(vaultCompatMount{Path: "pki", Type: "pki", Description: "trstctl dynamic PKI issuance"})
	}
	if a.transit != nil {
		mounts["transit/"] = vaultMountResponse(vaultCompatMount{Path: "transit", Type: "transit", Description: "trstctl transit encryption service"})
	}
	return mounts
}

func vaultMountResponse(mount vaultCompatMount) map[string]any {
	return map[string]any{
		"type": mount.Type, "description": mount.Description, "options": mount.Options,
		"config": map[string]any{}, "local": false, "seal_wrap": false,
		"external_entropy_access": false,
	}
}

//trstctl:mutation
func (a *API) vaultEnableMount(w http.ResponseWriter, r *http.Request) {
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	path, err := normalizeVaultMountPath(r.PathValue("path"))
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	key, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		var req vaultMountRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Type = strings.ToLower(strings.TrimSpace(req.Type))
		switch req.Type {
		case "kv", "kv-v2":
			req.Type = "kv"
			if version := strings.TrimSpace(req.Options["version"]); version != "" && version != "2" {
				return 0, nil, errStatus(http.StatusBadRequest, "only KV version 2 is supported")
			}
			req.Options = map[string]string{"version": "2"}
		case "pki":
			if a.secrets == nil {
				return 0, nil, errStatus(http.StatusNotImplemented, "PKI secret issuance is not enabled")
			}
		case "transit":
			if a.transit == nil {
				return 0, nil, transitDisabledProblem()
			}
		default:
			return 0, nil, errStatus(http.StatusBadRequest, "mount type must be kv, pki, or transit")
		}
		state, err := a.vaultCompat.snapshot(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		if _, exists := state.mounts[path]; exists || path == "secret" || path == "pki" || path == "transit" {
			return 0, nil, errStatus(http.StatusConflict, "path is already in use")
		}
		mount := vaultCompatMount{Path: path, Type: req.Type, Description: strings.TrimSpace(req.Description), Options: req.Options}
		if _, err := a.vaultCompat.append(ctx, tenantID, vaultMountEnabledEventType, mount); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

//trstctl:mutation
func (a *API) vaultDisableMount(w http.ResponseWriter, r *http.Request) {
	path, err := normalizeVaultMountPath(r.PathValue("path"))
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	key, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if path == "secret" || path == "pki" || path == "transit" {
			return 0, nil, errStatus(http.StatusBadRequest, "built-in mounts cannot be disabled")
		}
		state, err := a.vaultCompat.snapshot(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		mount, exists := state.mounts[path]
		if !exists {
			return 0, nil, errStatus(http.StatusNotFound, "no such mount")
		}
		if _, err := a.vaultCompat.append(ctx, tenantID, vaultMountDisabledEventType, mount); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) resolveVaultMount(r *http.Request, want string) error {
	mount := strings.Trim(r.PathValue("mount"), "/")
	if mount == want {
		if want == "transit" && a.transit == nil {
			return transitDisabledProblem()
		}
		return nil
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		return errStatus(http.StatusForbidden, "permission denied")
	}
	state, err := a.vaultCompat.snapshot(r.Context(), tenantID)
	if err != nil {
		return err
	}
	configured, ok := state.mounts[mount]
	if !ok || configured.Type != want {
		return errStatus(http.StatusNotFound, "no handler for route")
	}
	return nil
}

func (a *API) vaultMountedKVRead(w http.ResponseWriter, r *http.Request) {
	if err := a.resolveVaultMount(r, "kv"); err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	r.SetPathValue("name", strings.Trim(r.PathValue("mount"), "/")+"/"+strings.Trim(r.PathValue("name"), "/"))
	a.vaultKVRead(w, r)
}

func (a *API) vaultMountedKVWrite(w http.ResponseWriter, r *http.Request) {
	if err := a.resolveVaultMount(r, "kv"); err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	r.SetPathValue("name", strings.Trim(r.PathValue("mount"), "/")+"/"+strings.Trim(r.PathValue("name"), "/"))
	a.vaultKVWrite(w, r)
}

func (a *API) vaultMountedPKIIssue(w http.ResponseWriter, r *http.Request) {
	if err := a.resolveVaultMount(r, "pki"); err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	a.vaultPKIIssue(w, r)
}

func vaultHTTPStatus(err error) int {
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		return apiErr.status
	}
	return http.StatusInternalServerError
}

type vaultPolicyRequest struct {
	Policy string `json:"policy"`
}

func (a *API) vaultListPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	state, err := a.vaultCompat.snapshot(r.Context(), tenantID)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "policy projection unavailable")
		return
	}
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{"keys": sortedVaultPolicyNames(state.policies), "policies": sortedVaultPolicyNames(state.policies)}))
}

func (a *API) vaultReadPolicy(w http.ResponseWriter, r *http.Request) {
	name, err := normalizeVaultPolicyName(r.PathValue("name"))
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	state, err := a.vaultCompat.snapshot(r.Context(), tenantID)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "policy projection unavailable")
		return
	}
	policy, exists := state.policies[name]
	if !exists {
		writeVaultError(w, http.StatusNotFound, "no such policy")
		return
	}
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]string{"name": policy.Name, "policy": policy.Policy, "rules": policy.Policy}))
}

//trstctl:mutation
func (a *API) vaultPutPolicy(w http.ResponseWriter, r *http.Request) {
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	name, err := normalizeVaultPolicyName(r.PathValue("name"))
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	key, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		var req vaultPolicyRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Policy = strings.TrimSpace(req.Policy)
		if len(req.Policy) == 0 || len(req.Policy) > maxVaultPolicyBytes {
			return 0, nil, errStatus(http.StatusBadRequest, "policy must be non-empty and at most 256 KiB")
		}
		if _, err := parseVaultACL(req.Policy); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		if _, err := a.vaultCompat.append(ctx, tenantID, vaultPolicyPutEventType, vaultCompatPolicy{Name: name, Policy: req.Policy}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

//trstctl:mutation
func (a *API) vaultDeletePolicy(w http.ResponseWriter, r *http.Request) {
	name, err := normalizeVaultPolicyName(r.PathValue("name"))
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	key, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		state, err := a.vaultCompat.snapshot(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		if _, exists := state.policies[name]; !exists {
			return 0, nil, errStatus(http.StatusNotFound, "no such policy")
		}
		if _, err := a.vaultCompat.append(ctx, tenantID, vaultPolicyDeletedEventType, vaultCompatPolicy{Name: name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

type vaultACLRule struct {
	path         string
	capabilities map[string]bool
}

var (
	vaultACLPathBlock = regexp.MustCompile(`(?s)path\s+"([^"]+)"\s*\{(.*?)\}`)
	vaultACLCaps      = regexp.MustCompile(`(?s)capabilities\s*=\s*\[([^]]*)\]`)
	vaultACLQuoted    = regexp.MustCompile(`"([^"]+)"`)
)

func parseVaultACL(policy string) ([]vaultACLRule, error) {
	matches := vaultACLPathBlock.FindAllStringSubmatch(policy, -1)
	if len(matches) == 0 {
		return nil, errors.New("policy must contain at least one Vault path block")
	}
	rules := make([]vaultACLRule, 0, len(matches))
	for _, match := range matches {
		path := strings.Trim(strings.TrimSpace(match[1]), "/")
		capsMatch := vaultACLCaps.FindStringSubmatch(match[2])
		if path == "" || len(capsMatch) != 2 {
			return nil, errors.New("each path block must have a path and capabilities list")
		}
		caps := map[string]bool{}
		for _, quoted := range vaultACLQuoted.FindAllStringSubmatch(capsMatch[1], -1) {
			capability := strings.ToLower(strings.TrimSpace(quoted[1]))
			switch capability {
			case "create", "read", "update", "patch", "delete", "list", "sudo", "deny":
				caps[capability] = true
			default:
				return nil, fmt.Errorf("unsupported Vault capability %q", capability)
			}
		}
		if len(caps) == 0 {
			return nil, errors.New("capabilities list must not be empty")
		}
		rules = append(rules, vaultACLRule{path: path, capabilities: caps})
	}
	return rules, nil
}

func (a *API) vaultACLDecision(ctx context.Context, tenantID string, roles []string, requestPath, capability string) (allowed, governed bool, err error) {
	state, err := a.vaultCompat.snapshot(ctx, tenantID)
	if err != nil {
		return false, false, err
	}
	sort.Strings(roles)
	for _, role := range roles {
		policy, exists := state.policies[role]
		if !exists {
			continue
		}
		governed = true
		rules, err := parseVaultACL(policy.Policy)
		if err != nil {
			return false, true, err
		}
		for _, rule := range rules {
			if !vaultACLPathMatch(rule.path, requestPath) {
				continue
			}
			if rule.capabilities["deny"] {
				return false, true, nil
			}
			if rule.capabilities[capability] || (capability == "update" && rule.capabilities["create"]) || (capability == "create" && rule.capabilities["update"]) {
				allowed = true
			}
		}
	}
	return allowed, governed, nil
}

func vaultACLPathMatch(pattern, requestPath string) bool {
	pattern = strings.Trim(pattern, "/")
	requestPath = strings.Trim(requestPath, "/")
	parts := strings.Split(pattern, "/")
	req := strings.Split(requestPath, "/")
	for i, part := range parts {
		if part == "*" && i == len(parts)-1 {
			return len(req) >= i
		}
		if strings.HasSuffix(part, "*") && i == len(parts)-1 {
			if len(req) <= i {
				return false
			}
			return strings.HasPrefix(req[i], strings.TrimSuffix(part, "*"))
		}
		if len(req) <= i || (part != "+" && part != req[i]) {
			return false
		}
	}
	return len(req) == len(parts)
}

func vaultRequestCapability(r *http.Request) string {
	switch r.Method {
	case http.MethodGet:
		return "read"
	case "LIST":
		return "list"
	case http.MethodDelete:
		return "delete"
	default:
		return "update"
	}
}

type vaultTransitKeyRequest struct {
	Type string `json:"type"`
}

type vaultTransitInputRequest struct {
	Plaintext  []byte `json:"plaintext,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Input      []byte `json:"input,omitempty"`
	Context    []byte `json:"context,omitempty"`
	Signature  string `json:"signature,omitempty"`
}

type vaultTransitPlaintextEnvelope struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Plaintext secretJSONBytes `json:"plaintext"`
	} `json:"data"`
	Warnings any `json:"warnings"`
}

func (r vaultTransitPlaintextEnvelope) wipeSecrets() { r.Data.Plaintext.wipe() }

func (a *API) requireVaultTransit(w http.ResponseWriter, r *http.Request) (string, bool) {
	if err := a.resolveVaultMount(r, "transit"); err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return "", false
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" || strings.Contains(name, "/") {
		writeVaultError(w, http.StatusBadRequest, "transit key name is required")
		return "", false
	}
	if mount := strings.Trim(r.PathValue("mount"), "/"); mount != "transit" {
		name = mount + "/" + name
	}
	return name, true
}

//trstctl:mutation
func (a *API) vaultTransitCreateKey(w http.ResponseWriter, r *http.Request) {
	name, ok := a.requireVaultTransit(w, r)
	if !ok {
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	key, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		var req vaultTransitKeyRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		var kind transit.Kind
		switch strings.ToLower(strings.TrimSpace(req.Type)) {
		case "", "aes256-gcm96":
			kind = transit.KindAEAD
		case "hmac", "hmac-sha2-256":
			kind = transit.KindHMAC
		case "ecdsa-p256":
			kind = transit.KindSign
		default:
			return 0, nil, errStatus(http.StatusBadRequest, "unsupported Vault transit key type")
		}
		if _, err := a.transit.CreateKey(ctx, tenantID, name, kind); err != nil {
			return 0, nil, mapTransitError(err)
		}
		return http.StatusNoContent, nil, nil
	})
}

//trstctl:mutation
func (a *API) vaultTransitRotateKey(w http.ResponseWriter, r *http.Request) {
	name, ok := a.requireVaultTransit(w, r)
	if !ok {
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	key, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.transit.Rotate(ctx, tenantID, name); err != nil {
			return 0, nil, mapTransitError(err)
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) vaultTransitMutation(w http.ResponseWriter, r *http.Request, fn func(context.Context, string, string, vaultTransitInputRequest) (any, error)) {
	name, ok := a.requireVaultTransit(w, r)
	if !ok {
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	key, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		var req vaultTransitInputRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		defer secret.Wipe(req.Plaintext)
		defer secret.Wipe(req.Input)
		defer secret.Wipe(req.Context)
		data, err := fn(ctx, tenantID, name, req)
		if err != nil {
			return 0, nil, mapTransitError(err)
		}
		if _, sensitive := data.(secretResponse); sensitive {
			return http.StatusOK, data, nil
		}
		return http.StatusOK, newVaultEnvelope(data), nil
	})
}

func (a *API) vaultTransitEncrypt(w http.ResponseWriter, r *http.Request) {
	a.vaultTransitMutation(w, r, func(ctx context.Context, tenantID, name string, req vaultTransitInputRequest) (any, error) {
		if len(req.Plaintext) == 0 {
			return nil, errStatus(http.StatusBadRequest, "plaintext is required")
		}
		ciphertext, err := a.transit.Encrypt(ctx, tenantID, name, req.Plaintext, req.Context)
		if err != nil {
			return nil, err
		}
		return map[string]string{"ciphertext": vaultCiphertextFromNative(ciphertext)}, nil
	})
}

func (a *API) vaultTransitDecrypt(w http.ResponseWriter, r *http.Request) {
	a.vaultTransitMutation(w, r, func(ctx context.Context, tenantID, name string, req vaultTransitInputRequest) (any, error) {
		ciphertext, err := nativeCiphertextFromVault(req.Ciphertext)
		if err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
		plaintext, err := a.transit.Decrypt(ctx, tenantID, name, ciphertext, req.Context)
		if err != nil {
			return nil, err
		}
		encoded := base64.StdEncoding.AppendEncode(nil, plaintext)
		secret.Wipe(plaintext)
		response := vaultTransitPlaintextEnvelope{RequestID: vaultCompatRequestID}
		response.Data.Plaintext = secretJSONBytes(encoded)
		return response, nil
	})
}

func (a *API) vaultTransitRewrap(w http.ResponseWriter, r *http.Request) {
	a.vaultTransitMutation(w, r, func(ctx context.Context, tenantID, name string, req vaultTransitInputRequest) (any, error) {
		ciphertext, err := nativeCiphertextFromVault(req.Ciphertext)
		if err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
		out, err := a.transit.Rewrap(ctx, tenantID, name, ciphertext, req.Context)
		if err != nil {
			return nil, err
		}
		return map[string]string{"ciphertext": vaultCiphertextFromNative(out)}, nil
	})
}

func (a *API) vaultTransitHMAC(w http.ResponseWriter, r *http.Request) {
	a.vaultTransitMutation(w, r, func(ctx context.Context, tenantID, name string, req vaultTransitInputRequest) (any, error) {
		if len(req.Input) == 0 {
			return nil, errStatus(http.StatusBadRequest, "input is required")
		}
		mac, err := a.transit.HMAC(ctx, tenantID, name, req.Input)
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(mac)
		return map[string]string{"hmac": "vault:v1:" + base64.StdEncoding.EncodeToString(mac)}, nil
	})
}

func (a *API) vaultTransitSign(w http.ResponseWriter, r *http.Request) {
	a.vaultTransitMutation(w, r, func(ctx context.Context, tenantID, name string, req vaultTransitInputRequest) (any, error) {
		if len(req.Input) == 0 {
			return nil, errStatus(http.StatusBadRequest, "input is required")
		}
		sig, publicDER, err := a.transit.Sign(ctx, tenantID, name, req.Input)
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(sig)
		defer secret.Wipe(publicDER)
		packed := make([]byte, 4, 4+len(publicDER)+len(sig))
		binary.BigEndian.PutUint32(packed, uint32(len(publicDER)))
		packed = append(packed, publicDER...)
		packed = append(packed, sig...)
		defer secret.Wipe(packed)
		return map[string]string{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(packed)}, nil
	})
}

func (a *API) vaultTransitVerify(w http.ResponseWriter, r *http.Request) {
	a.vaultTransitMutation(w, r, func(ctx context.Context, tenantID, _ string, req vaultTransitInputRequest) (any, error) {
		if len(req.Input) == 0 {
			return nil, errStatus(http.StatusBadRequest, "input is required")
		}
		packed, err := decodeVaultVersionedValue(req.Signature)
		if err != nil {
			return nil, errStatus(http.StatusBadRequest, "signature is malformed")
		}
		defer secret.Wipe(packed)
		if len(packed) < 5 {
			return nil, errStatus(http.StatusBadRequest, "signature is malformed")
		}
		publicLen := int(binary.BigEndian.Uint32(packed[:4]))
		if publicLen <= 0 || publicLen >= len(packed)-4 {
			return nil, errStatus(http.StatusBadRequest, "signature is malformed")
		}
		err = a.transit.Verify(ctx, tenantID, req.Input, packed[4+publicLen:], packed[4:4+publicLen])
		return map[string]bool{"valid": err == nil}, nil
	})
}

func vaultCiphertextFromNative(value string) string {
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 || parts[0] != "trv" {
		return value
	}
	return "vault:v" + parts[1] + ":" + parts[2]
}

func nativeCiphertextFromVault(value string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(value), ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") || len(parts[1]) == 1 || parts[2] == "" {
		return "", errors.New("ciphertext must use vault:vN: encoding")
	}
	return "trv:" + strings.TrimPrefix(parts[1], "v") + ":" + parts[2], nil
}

func decodeVaultVersionedValue(value string) ([]byte, error) {
	parts := strings.SplitN(strings.TrimSpace(value), ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return nil, errors.New("invalid Vault versioned value")
	}
	return base64.StdEncoding.DecodeString(parts[2])
}
