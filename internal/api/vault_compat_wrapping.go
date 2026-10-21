// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// Response wrapping and the per-token cubbyhole on the Vault/OpenBao shim.
//
// Wrapping reuses the native one-time share rows: the payload is sealed under
// the tenant key domain and stored under SHA-256(wrapping token) with a TTL;
// lookup reads the metadata without consuming, unwrap is the single-use
// DELETE ... RETURNING the native share redeem uses. The cubbyhole is a
// per-token scratch space keyed by SHA-256(API token) and path; its entries
// expire with the token when the token has an expiry.

const (
	vaultWrapTokenPrefix  = "trstw_"
	vaultWrapDefaultTTL   = 5 * time.Minute
	vaultWrapMaxTTL       = 24 * time.Hour
	vaultCubbyholeBodyMax = 1 << 16
)

var vaultCompatWrappingRoutes = []vaultCompatRoute{
	{
		method: http.MethodPost, pattern: "/v1/sys/wrapping/wrap", contractPath: "/v1/sys/wrapping/wrap",
		samplePath: "/v1/sys/wrapping/wrap", sampleBody: `{"password":"one-time"}`, operationID: "vaultCompatWrappingWrap",
		summary:     "Wrap a JSON payload under a single-use wrapping token (X-Vault-Wrap-TTL, default 5m) sealed in the tenant key domain",
		successCode: "200", tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest", responseSchema: "VaultWrapResponse",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultWrappingWrap) },
	},
	{
		method: http.MethodPost, pattern: "/v1/sys/wrapping/unwrap", contractPath: "/v1/sys/wrapping/unwrap",
		samplePath: "/v1/sys/wrapping/unwrap", sampleBody: `{"token":"trstw_..."}`, operationID: "vaultCompatWrappingUnwrap",
		summary:     "Return a wrapped payload exactly once and consume the wrapping token",
		successCode: "200", tokenRequired: true, mutation: true, requestSchema: "VaultWrappingTokenRequest", responseSchema: "VaultGenericResponse", sensitiveResponse: true,
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultWrappingUnwrap) },
	},
	{
		method: http.MethodPost, pattern: "/v1/sys/wrapping/lookup", contractPath: "/v1/sys/wrapping/lookup",
		samplePath: "/v1/sys/wrapping/lookup", sampleBody: `{"token":"trstw_..."}`, operationID: "vaultCompatWrappingLookup",
		summary:     "Report a wrapping token's creation time and TTL without consuming it",
		successCode: "200", tokenRequired: true, requestSchema: "VaultWrappingTokenRequest", responseSchema: "VaultWrapLookupResponse",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultWrappingLookup) },
	},
	{
		method: http.MethodGet, pattern: "/v1/{mount}/{path...}", contractPath: "/v1/cubbyhole/{path}",
		samplePath: "/v1/cubbyhole/scratch/note", operationID: "vaultCompatCubbyholeRead",
		summary:     "Read an entry of the presented token's cubbyhole (or LIST a folder with ?list=true)",
		successCode: "200", tokenRequired: true, responseSchema: "VaultGenericResponse", sensitiveResponse: true,
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultCubbyholeReadOrList) },
	},
	{
		method: "LIST", pattern: "/v1/{mount}/{path...}", contractPath: "/v1/cubbyhole/{path}",
		samplePath: "/v1/cubbyhole/scratch", operationID: "vaultCompatCubbyholeList",
		summary:     "List the direct children of a folder in the presented token's cubbyhole",
		successCode: "200", tokenRequired: true, responseSchema: "VaultKVListResponse",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultCubbyholeList) },
	},
	{
		method: http.MethodPost, pattern: "/v1/{mount}/{path...}", contractPath: "/v1/cubbyhole/{path}",
		samplePath: "/v1/cubbyhole/scratch/note", sampleBody: `{"value":"mine"}`, operationID: "vaultCompatCubbyholeWrite",
		summary:     "Write an entry of the presented token's cubbyhole, sealed in the tenant key domain",
		successCode: "204", tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultCubbyholeWrite) },
	},
	{
		method: http.MethodPut, pattern: "/v1/{mount}/{path...}", contractPath: "/v1/cubbyhole/{path}",
		samplePath: "/v1/cubbyhole/scratch/note", sampleBody: `{"value":"mine"}`, operationID: "vaultCompatCubbyholeWritePut",
		summary:     "Write an entry of the presented token's cubbyhole, sealed in the tenant key domain",
		successCode: "204", tokenRequired: true, mutation: true, requestSchema: "VaultGenericRequest",
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultCubbyholeWrite) },
	},
	{
		method: http.MethodDelete, pattern: "/v1/{mount}/{path...}", contractPath: "/v1/cubbyhole/{path}",
		samplePath: "/v1/cubbyhole/scratch/note", operationID: "vaultCompatCubbyholeDelete",
		summary:     "Delete an entry of the presented token's cubbyhole",
		successCode: "204", tokenRequired: true, mutation: true,
		handler: func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultCubbyholeDelete) },
	},
}

func vaultCompatWrappingSchemas(schemas map[string]*Schema) {
	anySchema := &Schema{}
	schemas["VaultWrappingTokenRequest"] = object(map[string]*Schema{"token": str()}, "token")
	schemas["VaultWrapInfo"] = object(map[string]*Schema{
		"token":         str(),
		"ttl":           {Type: "integer"},
		"creation_time": timestamp(),
		"creation_path": str(),
	}, "token", "ttl", "creation_time", "creation_path")
	schemas["VaultWrapResponse"] = object(map[string]*Schema{
		"request_id":     str(),
		"lease_id":       str(),
		"renewable":      {Type: "boolean"},
		"lease_duration": {Type: "integer"},
		"data":           anySchema,
		"wrap_info":      ref("VaultWrapInfo"),
		"warnings":       anySchema,
	}, "request_id", "wrap_info")
	schemas["VaultWrapLookupData"] = object(map[string]*Schema{
		"creation_time": timestamp(),
		"creation_ttl":  {Type: "integer"},
		"creation_path": str(),
	}, "creation_time", "creation_ttl", "creation_path")
	schemas["VaultWrapLookupResponse"] = vaultCompatEnvelope("VaultWrapLookupData", anySchema)
}

func vaultWrapAAD(tenantID, shareID, tokenHash string) []byte {
	return []byte("trstctl.vault-wrap.v1\x00" + tenantID + "\x00" + shareID + "\x00" + tokenHash)
}

func vaultWrapTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return vaultWrapDefaultTTL, nil
	}
	var ttl time.Duration
	if seconds, err := strconv.Atoi(raw); err == nil {
		ttl = time.Duration(seconds) * time.Second
	} else if d, err := time.ParseDuration(raw); err == nil {
		ttl = d
	} else {
		return 0, errors.New("X-Vault-Wrap-TTL must be seconds or a duration such as 5m")
	}
	if ttl < time.Second || ttl > vaultWrapMaxTTL {
		return 0, errors.New("X-Vault-Wrap-TTL must be between 1s and 24h")
	}
	return ttl, nil
}

func (a *API) vaultWrappingWrap(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	if !rawJSONObject(body) {
		writeVaultError(w, http.StatusBadRequest, "wrap body must be a JSON object")
		return
	}
	ttl, err := vaultWrapTTL(r.Header.Get("X-Vault-Wrap-TTL"))
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	tokenRaw, err := crypto.RandomBytes(32)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(tokenRaw)
	token := append([]byte(vaultWrapTokenPrefix), crypto.AppendHex(nil, tokenRaw)...)
	defer secret.Wipe(token)
	tokenHash := crypto.SHA256Hex(token)
	shareRaw, err := crypto.RandomBytes(16)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	shareID := "wrap-" + string(crypto.AppendHex(nil, shareRaw))
	secret.Wipe(shareRaw)
	sealed, err := a.secrets.seal(r.Context(), tenantID, body, vaultWrapAAD(tenantID, shareID, tokenHash))
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := time.Now().UTC()
	if err := a.secrets.be.Store.PutSecretShare(r.Context(), tenantID, tokenHash, shareID, sealed, now.Add(ttl)); err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"request_id":"` + vaultCompatRequestID + `","lease_id":"","renewable":false,"lease_duration":0,"data":null,"wrap_info":{"token":`))
	quoted := appendJSONQuotedBytes(nil, token)
	_, _ = w.Write(quoted)
	secret.Wipe(quoted)
	_, _ = w.Write([]byte(`,"ttl":` + strconv.Itoa(int(ttl/time.Second)) + `,"creation_time":"` + now.Format(time.RFC3339Nano) + `","creation_path":"sys/wrapping/wrap"},"warnings":null}`))
}

type vaultWrappingTokenRequest struct {
	Token secretJSONBytes `json:"token"`
}

func (a *API) vaultWrappingToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req vaultWrappingTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || len(req.Token) == 0 {
		writeVaultError(w, http.StatusBadRequest, "token is required")
		return "", false
	}
	defer req.Token.wipe()
	if !bytes.HasPrefix(req.Token, []byte(vaultWrapTokenPrefix)) {
		writeVaultError(w, http.StatusBadRequest, "wrapping token is invalid")
		return "", false
	}
	return crypto.SHA256Hex(req.Token), true
}

func (a *API) vaultWrappingUnwrap(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	tokenHash, ok := a.vaultWrappingToken(w, r)
	if !ok {
		return
	}
	share, err := a.secrets.be.Store.ConsumeSecretShare(r.Context(), tenantID, tokenHash, time.Now())
	if err != nil {
		if errors.Is(err, store.ErrSecretShareNotFound) {
			writeVaultError(w, http.StatusBadRequest, "wrapping token is not valid, has expired, or was already unwrapped")
			return
		}
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !strings.HasPrefix(share.ShareID, "wrap-") {
		writeVaultError(w, http.StatusBadRequest, "token is a native one-time share, not a wrapping token")
		return
	}
	value, err := a.secrets.open(r.Context(), tenantID, share.Sealed, vaultWrapAAD(tenantID, share.ShareID, share.TokenHash))
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(value)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"request_id":"` + vaultCompatRequestID + `","lease_id":"","renewable":false,"lease_duration":0,"data":`))
	_, _ = w.Write(value)
	_, _ = w.Write([]byte(`,"warnings":null}`))
}

func (a *API) vaultWrappingLookup(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	tokenHash, ok := a.vaultWrappingToken(w, r)
	if !ok {
		return
	}
	share, err := a.secrets.be.Store.LookupSecretShare(r.Context(), tenantID, tokenHash, time.Now())
	if err != nil || !strings.HasPrefix(share.ShareID, "wrap-") {
		if err == nil || errors.Is(err, store.ErrSecretShareNotFound) {
			writeVaultError(w, http.StatusBadRequest, "wrapping token is not valid, has expired, or was already unwrapped")
			return
		}
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
		"creation_time": share.CreatedAt.UTC().Format(time.RFC3339Nano),
		"creation_ttl":  int(share.ExpiresAt.Sub(share.CreatedAt) / time.Second),
		"creation_path": "sys/wrapping/wrap",
	}))
}

// vaultCubbyholeToken identifies the presented API token's cubbyhole and its
// expiry. The token itself is only hashed; the hash is the row key.
func (a *API) vaultCubbyholeToken(w http.ResponseWriter, r *http.Request) (tenantID, tokenHash string, expires *time.Time, ok bool) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return "", "", nil, false
	}
	principal, found := a.principalFor(r)
	if !found {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return "", "", nil, false
	}
	token := bearerTokenBytes(r)
	if len(token) == 0 {
		writeVaultError(w, http.StatusForbidden, "cubbyhole requires a Vault API token")
		return "", "", nil, false
	}
	defer secret.Wipe(token)
	hash, err := auth.HashAPIToken(token)
	if err != nil {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return "", "", nil, false
	}
	if a.store != nil {
		if rec, err := a.store.LookupAPITokenByHash(r.Context(), hash); err == nil && rec.ExpiresAt != nil {
			at := rec.ExpiresAt.UTC()
			expires = &at
		}
	}
	return principal.TenantID, hash, expires, true
}

// vaultCubbyholePath reads the entry path. The cubbyhole routes are registered
// on the shim's generic /v1/{mount}/{path} shape (a literal /v1/cubbyhole/...
// pattern would be ambiguous with the mounted-KV /v1/{mount}/data/... family
// for Go's mux), so every handler first checks the mount is the cubbyhole.
func vaultCubbyholePath(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.PathValue("mount") != "cubbyhole" {
		writeVaultError(w, http.StatusNotFound, "unsupported path")
		return "", false
	}
	path := strings.Trim(r.PathValue("path"), "/")
	if path == "" {
		writeVaultError(w, http.StatusBadRequest, "cubbyhole path is required")
		return "", false
	}
	return path, true
}

func (a *API) vaultCubbyholeWrite(w http.ResponseWriter, r *http.Request) {
	tenantID, tokenHash, expires, ok := a.vaultCubbyholeToken(w, r)
	if !ok {
		return
	}
	path, ok := vaultCubbyholePath(w, r)
	if !ok {
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	if len(body) > vaultCubbyholeBodyMax || !rawJSONObject(body) {
		writeVaultError(w, http.StatusBadRequest, "cubbyhole body must be a JSON object under 64 KiB")
		return
	}
	sealed, err := a.secrets.seal(r.Context(), tenantID, body, vaultCubbyholeAAD(tenantID, tokenHash, path))
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := a.secrets.be.Store.PutVaultCubbyhole(r.Context(), tenantID, tokenHash, path, sealed, expires); err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func vaultCubbyholeAAD(tenantID, tokenHash, path string) []byte {
	return []byte("trstctl.vault-cubbyhole.v1\x00" + tenantID + "\x00" + tokenHash + "\x00" + path)
}

func (a *API) vaultCubbyholeReadOrList(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("list") == "true" {
		a.vaultCubbyholeList(w, r)
		return
	}
	tenantID, tokenHash, _, ok := a.vaultCubbyholeToken(w, r)
	if !ok {
		return
	}
	path, ok := vaultCubbyholePath(w, r)
	if !ok {
		return
	}
	entry, err := a.secrets.be.Store.GetVaultCubbyhole(r.Context(), tenantID, tokenHash, path, time.Now())
	if err != nil {
		if errors.Is(err, store.ErrVaultCubbyholeNotFound) {
			writeVaultError(w, http.StatusNotFound, "no such cubbyhole entry")
			return
		}
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	value, err := a.secrets.open(r.Context(), tenantID, entry.Sealed, vaultCubbyholeAAD(tenantID, tokenHash, path))
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(value)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"request_id":"` + vaultCompatRequestID + `","lease_id":"","renewable":false,"lease_duration":0,"data":`))
	_, _ = w.Write(value)
	_, _ = w.Write([]byte(`,"warnings":null}`))
}

func (a *API) vaultCubbyholeList(w http.ResponseWriter, r *http.Request) {
	tenantID, tokenHash, _, ok := a.vaultCubbyholeToken(w, r)
	if !ok {
		return
	}
	if r.PathValue("mount") != "cubbyhole" {
		writeVaultError(w, http.StatusNotFound, "unsupported path")
		return
	}
	prefix := strings.Trim(r.PathValue("path"), "/")
	if prefix != "" {
		prefix += "/"
	}
	paths, err := a.secrets.be.Store.ListVaultCubbyhole(r.Context(), tenantID, tokenHash, prefix, time.Now())
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	seen := map[string]bool{}
	for _, p := range paths {
		rest := strings.TrimPrefix(p, prefix)
		if child, _, nested := strings.Cut(rest, "/"); nested {
			seen[child+"/"] = true
		} else if rest != "" {
			seen[rest] = true
		}
	}
	if len(seen) == 0 {
		writeVaultError(w, http.StatusNotFound, "no cubbyhole entries under this path")
		return
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{"keys": keys}))
}

func (a *API) vaultCubbyholeDelete(w http.ResponseWriter, r *http.Request) {
	tenantID, tokenHash, _, ok := a.vaultCubbyholeToken(w, r)
	if !ok {
		return
	}
	path, ok := vaultCubbyholePath(w, r)
	if !ok {
		return
	}
	if err := a.secrets.be.Store.DeleteVaultCubbyhole(r.Context(), tenantID, tokenHash, path); err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Permission-neutral by design: a token may only ever touch its own hole.
	_ = authz.SecretsWrite
	w.WriteHeader(http.StatusNoContent)
}
