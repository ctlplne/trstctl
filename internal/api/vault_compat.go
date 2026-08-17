// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	vaultCompatRequestID = "trstctl-vault-compat"
	vaultKVSecretMount   = "secret"
	vaultPKIMount        = "pki"
)

type vaultCompatRoute struct {
	method            string
	pattern           string
	contractPath      string
	samplePath        string
	sampleBody        string
	operationID       string
	summary           string
	successCode       string
	permission        authz.Permission
	tokenRequired     bool
	mutation          bool
	requestSchema     string
	responseSchema    string
	sensitiveResponse bool
	handler           func(*API) http.HandlerFunc
}

var vaultCompatRoutes = []vaultCompatRoute{
	{
		method:         http.MethodGet,
		pattern:        "/v1/sys/health",
		contractPath:   "/v1/sys/health",
		samplePath:     "/v1/sys/health",
		operationID:    "vaultCompatHealth",
		summary:        "Report Vault/OpenBao-compatible shim health",
		successCode:    "200",
		responseSchema: "VaultHealthResponse",
		handler:        func(a *API) http.HandlerFunc { return a.vaultHealth },
	},
	{
		method:         http.MethodGet,
		pattern:        "/v1/sys/internal/ui/mounts/{path...}",
		contractPath:   "/v1/sys/internal/ui/mounts/{path}",
		samplePath:     "/v1/sys/internal/ui/mounts/secret/data/payments/db",
		operationID:    "vaultCompatMountInfo",
		summary:        "Discover the supported Vault/OpenBao-compatible mount type",
		successCode:    "200",
		tokenRequired:  true,
		responseSchema: "VaultMountInfoResponse",
		handler:        func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultMountInfo) },
	},
	{
		method:         http.MethodGet,
		pattern:        "/v1/auth/token/lookup-self",
		contractPath:   "/v1/auth/token/lookup-self",
		samplePath:     "/v1/auth/token/lookup-self",
		operationID:    "vaultCompatTokenLookupSelf",
		summary:        "Return Vault/OpenBao-shaped metadata for the trstctl API token",
		successCode:    "200",
		tokenRequired:  true,
		responseSchema: "VaultTokenLookupSelfResponse",
		handler:        func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultTokenLookupSelf) },
	},
	{
		method:         http.MethodPost,
		pattern:        "/v1/auth/token/lookup-self",
		contractPath:   "/v1/auth/token/lookup-self",
		samplePath:     "/v1/auth/token/lookup-self",
		operationID:    "vaultCompatTokenLookupSelfPost",
		summary:        "Return Vault/OpenBao-shaped metadata for the trstctl API token",
		successCode:    "200",
		tokenRequired:  true,
		responseSchema: "VaultTokenLookupSelfResponse",
		handler:        func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultTokenLookupSelf) },
	},
	{
		method:            http.MethodGet,
		pattern:           "/v1/secret/data/{name...}",
		contractPath:      "/v1/secret/data/{name}",
		samplePath:        "/v1/secret/data/payments/db",
		operationID:       "vaultCompatKVRead",
		summary:           "Read a Vault KV v2 object from the served trstctl secret store",
		successCode:       "200",
		permission:        authz.SecretsRead,
		tokenRequired:     true,
		responseSchema:    "VaultKVReadResponse",
		sensitiveResponse: true,
		handler:           func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsRead, a.vaultKVRead) },
	},
	{
		method:         http.MethodPost,
		pattern:        "/v1/secret/data/{name...}",
		contractPath:   "/v1/secret/data/{name}",
		samplePath:     "/v1/secret/data/payments/db",
		sampleBody:     `{"data":{"username":"payments"}}`,
		operationID:    "vaultCompatKVWrite",
		summary:        "Write a Vault KV v2 object into the served trstctl secret store",
		successCode:    "200",
		permission:     authz.SecretsWrite,
		tokenRequired:  true,
		mutation:       true,
		requestSchema:  "VaultKVWriteRequest",
		responseSchema: "VaultKVWriteResponse",
		handler:        func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultKVWrite) },
	},
	{
		method:         http.MethodPut,
		pattern:        "/v1/secret/data/{name...}",
		contractPath:   "/v1/secret/data/{name}",
		samplePath:     "/v1/secret/data/payments/db",
		sampleBody:     `{"data":{"username":"payments"}}`,
		operationID:    "vaultCompatKVWritePut",
		summary:        "Write a Vault KV v2 object into the served trstctl secret store",
		successCode:    "200",
		permission:     authz.SecretsWrite,
		tokenRequired:  true,
		mutation:       true,
		requestSchema:  "VaultKVWriteRequest",
		responseSchema: "VaultKVWriteResponse",
		handler:        func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultKVWrite) },
	},
	{
		method:            http.MethodPost,
		pattern:           "/v1/pki/issue/{role}",
		contractPath:      "/v1/pki/issue/{role}",
		samplePath:        "/v1/pki/issue/default",
		sampleBody:        `{"common_name":"svc.example.test","ttl":"1h"}`,
		operationID:       "vaultCompatPKIIssue",
		summary:           "Issue a Vault/OpenBao-shaped short-lived certificate and private key",
		successCode:       "200",
		permission:        authz.SecretsWrite,
		tokenRequired:     true,
		mutation:          true,
		requestSchema:     "VaultPKIIssueRequest",
		responseSchema:    "VaultPKIIssueResponse",
		sensitiveResponse: true,
		handler:           func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultPKIIssue) },
	},
	{
		method:            http.MethodPut,
		pattern:           "/v1/pki/issue/{role}",
		contractPath:      "/v1/pki/issue/{role}",
		samplePath:        "/v1/pki/issue/default",
		sampleBody:        `{"common_name":"svc.example.test","ttl":"1h"}`,
		operationID:       "vaultCompatPKIIssuePut",
		summary:           "Issue a Vault/OpenBao-shaped short-lived certificate and private key",
		successCode:       "200",
		permission:        authz.SecretsWrite,
		tokenRequired:     true,
		mutation:          true,
		requestSchema:     "VaultPKIIssueRequest",
		responseSchema:    "VaultPKIIssueResponse",
		sensitiveResponse: true,
		handler:           func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultPKIIssue) },
	},
	{
		method:            http.MethodPost,
		pattern:           "/v1/pki/sign/{role}",
		contractPath:      "/v1/pki/sign/{role}",
		samplePath:        "/v1/pki/sign/default",
		sampleBody:        `{"csr":"-----BEGIN CERTIFICATE REQUEST-----\\n...\\n-----END CERTIFICATE REQUEST-----","ttl":"1h"}`,
		operationID:       "vaultCompatPKISign",
		summary:           "Sign a requester-generated CSR without receiving or returning its private key",
		successCode:       "200",
		permission:        authz.SecretsWrite,
		tokenRequired:     true,
		mutation:          true,
		requestSchema:     "VaultPKISignRequest",
		responseSchema:    "VaultPKISignResponse",
		sensitiveResponse: true,
		handler:           func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultPKISign) },
	},
	{
		method:            http.MethodPut,
		pattern:           "/v1/pki/sign/{role}",
		contractPath:      "/v1/pki/sign/{role}",
		samplePath:        "/v1/pki/sign/default",
		sampleBody:        `{"csr":"-----BEGIN CERTIFICATE REQUEST-----\\n...\\n-----END CERTIFICATE REQUEST-----","ttl":"1h"}`,
		operationID:       "vaultCompatPKISignPut",
		summary:           "Sign a requester-generated CSR without receiving or returning its private key",
		successCode:       "200",
		permission:        authz.SecretsWrite,
		tokenRequired:     true,
		mutation:          true,
		requestSchema:     "VaultPKISignRequest",
		responseSchema:    "VaultPKISignResponse",
		sensitiveResponse: true,
		handler:           func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultPKISign) },
	},
}

// mountVaultCompat registers VAULT-01's compatibility shim. These are not native
// trstctl API resources, so they stay out of the OpenAPI registry, but every
// state-changing path still goes through the same tenant, RBAC, idempotency, audit,
// and sealed-at-rest implementation as /api/v1/secrets/*.
func (a *API) mountVaultCompat(mux *http.ServeMux) {
	for _, rt := range allVaultCompatRoutes() {
		mux.HandleFunc(rt.method+" "+rt.pattern, rt.handler(a))
	}
	a.mountVaultTransitRoutes(mux)
}

func (a *API) vaultAuth(perm authz.Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.principal(r)
		if err != nil {
			writeVaultError(w, http.StatusForbidden, "permission denied")
			return
		}
		if !tenantHeaderMatchesPrincipal(r, principal) {
			writeVaultError(w, http.StatusForbidden, "permission denied")
			return
		}
		if perm != "" {
			target := authz.Scope{TenantID: principal.TenantID, Project: r.Header.Get("X-Project")}
			if !principal.Can(perm, target) {
				writeVaultError(w, http.StatusForbidden, "permission denied")
				return
			}
			if err := a.checkABAC(r.Context(), r, principal, perm, target); err != nil {
				writeVaultError(w, vaultStatus(err), err.Error())
				return
			}
		}
		requestPath := strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "v1/")
		allowed, governed, err := a.vaultACLDecision(r.Context(), principal.TenantID, principalRoles(principal), requestPath, vaultRequestCapability(r))
		if err != nil {
			writeVaultError(w, http.StatusInternalServerError, "ACL policy projection unavailable")
			return
		}
		if governed && !allowed {
			writeVaultError(w, http.StatusForbidden, "permission denied by Vault ACL policy")
			return
		}
		if a.rateLimiter != nil {
			allowed, retryAfter, err := a.rateLimiter.Allow(r.Context(), principal.TenantID)
			if err != nil {
				writeVaultError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if !allowed {
				if retryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds()+0.999)))
				}
				writeVaultError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		ctx := context.WithValue(r.Context(), principalCtxKey, principal)
		ctx = events.ContextWithActor(ctx, events.Actor{Subject: principal.Subject, Roles: principalRoles(principal)})
		request := r.WithContext(ctx)
		if a.secrets == nil || a.secrets.be.TenantCrypto == nil {
			h(w, request)
			return
		}
		err = a.secrets.withTenantCipher(ctx, principal.TenantID, func(cipher tenantseal.Cipher) error {
			requestCtx := context.WithValue(ctx, tenantCipherCtxKey, cipher)
			h(w, request.WithContext(requestCtx))
			return nil
		})
		if err == nil {
			return
		}
		if status, ok := tenantseal.StatusOf(err); ok {
			writeVaultError(w, http.StatusLocked, "tenant cryptographic access is unavailable: "+string(status))
			return
		}
		writeVaultError(w, http.StatusInternalServerError, "tenant cryptographic access is unavailable")
	}
}

func vaultStatus(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.status
	}
	return http.StatusForbidden
}

type vaultEnvelope struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          any    `json:"data,omitempty"`
	Warnings      any    `json:"warnings"`
}

func newVaultEnvelope(data any) vaultEnvelope {
	return vaultEnvelope{
		RequestID: vaultCompatRequestID,
		Data:      data,
		Warnings:  nil,
	}
}

func writeVaultJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeVaultError(w http.ResponseWriter, status int, detail string) {
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if detail == "" {
		detail = http.StatusText(status)
	}
	writeVaultJSON(w, status, map[string][]string{"errors": {detail}})
}

func (a *API) vaultHealth(w http.ResponseWriter, _ *http.Request) {
	writeVaultJSON(w, http.StatusOK, map[string]any{
		"initialized": true,
		"sealed":      false,
		"standby":     false,
		"version":     "trstctl-vault-compat",
	})
}

func (a *API) vaultMountInfo(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.PathValue("path"), "/")
	switch {
	case path == vaultKVSecretMount || strings.HasPrefix(path, vaultKVSecretMount+"/"):
		writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
			"path":    vaultKVSecretMount + "/",
			"type":    "kv",
			"options": map[string]string{"version": "2"},
		}))
	case path == vaultPKIMount || strings.HasPrefix(path, vaultPKIMount+"/"):
		writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
			"path": vaultPKIMount + "/",
			"type": "pki",
		}))
	case path == "transit" || strings.HasPrefix(path, "transit/"):
		if a.transit == nil {
			writeVaultError(w, http.StatusNotFound, "no handler for route")
			return
		}
		writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
			"path": "transit/",
			"type": "transit",
		}))
	default:
		if a.tenantFn == nil {
			writeVaultError(w, http.StatusNotFound, "no handler for route")
			return
		}
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
		mountName, _, _ := strings.Cut(path, "/")
		mount, exists := state.mounts[mountName]
		if !exists {
			writeVaultError(w, http.StatusNotFound, "no handler for route")
			return
		}
		writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
			"path":    mount.Path + "/",
			"type":    mount.Type,
			"options": mount.Options,
		}))
	}
}

func (a *API) vaultTokenLookupSelf(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.principalFor(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
		"id":           "trstctl-api-token",
		"accessor":     "",
		"display_name": principal.Subject,
		"entity_id":    principal.Subject,
		"meta":         map[string]string{"tenant_id": principal.TenantID},
		"num_uses":     0,
		"orphan":       true,
		"path":         "auth/token/create",
		"policies":     principalRoles(principal),
		"renewable":    false,
		"ttl":          0,
	}))
}

type vaultKVWriteRequest struct {
	Data    json.RawMessage            `json:"data"`
	Options map[string]json.RawMessage `json:"options,omitempty"`
}

type vaultKVMetadata struct {
	CreatedTime  string         `json:"created_time"`
	DeletionTime string         `json:"deletion_time"`
	Destroyed    bool           `json:"destroyed"`
	Version      int            `json:"version"`
	Custom       map[string]any `json:"custom_metadata"`
}

//trstctl:mutation
func (a *API) vaultKVWrite(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	name := strings.Trim(r.PathValue("name"), "/")
	if name == "" {
		writeVaultError(w, http.StatusBadRequest, "secret path is required")
		return
	}
	idempotencyKey, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	var req vaultKVWriteRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer secret.Wipe(req.Data)
	defer func() {
		for key, raw := range req.Options {
			secret.Wipe(raw)
			delete(req.Options, key)
		}
	}()
	if !rawJSONObject(req.Data) {
		a.writeError(w, errStatus(http.StatusBadRequest, "data must be a JSON object"))
		return
	}
	value := append([]byte(nil), req.Data...)
	defer secret.Wipe(value)
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	bindingTenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	keyDigest, requestBinding, err := a.applicationSecretRequestBinding(
		bindingTenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(), "write", "vault", name, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if tenantID != bindingTenantID {
			return 0, nil, errors.New("api: application-secret binding tenant changed")
		}
		rec, err := a.upsertVaultKVSecret(
			ctx, tenantID, name, value, idempotencyKey, keyDigest, requestBinding)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, newVaultEnvelope(vaultKVMetadata{
			CreatedTime:  rec.UpdatedAt.UTC().Format(time.RFC3339Nano),
			DeletionTime: "",
			Destroyed:    false,
			Version:      rec.Version,
			Custom:       nil,
		}), nil
	})
}

func (a *API) upsertVaultKVSecret(
	ctx context.Context,
	tenantID, name string,
	plaintext []byte,
	idempotencyKey, keyDigest, requestBinding string,
) (store.Secret, error) {
	const operation = "vault-write"
	tenantEpoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return store.Secret{}, err
	}
	eventID := applicationSecretMutationEventID(tenantID, tenantEpoch, name, operation, keyDigest)
	if receipt, ok, err := a.applicationSecretMaterializedResult(
		ctx, tenantID, eventID, requestBinding, name, "create", "rotate"); err != nil {
		return store.Secret{}, applicationSecretMutationError(err)
	} else if ok {
		return store.Secret{
			TenantID: receipt.TenantID, Name: receipt.Name, Version: receipt.ResultVersion,
			CreatedAt: receipt.ResultCreatedAt, UpdatedAt: receipt.ResultUpdatedAt,
		}, nil
	}
	fence, payload, prepared, err := a.applicationSecretMutationFence(
		ctx, tenantID, name, operation, eventID, requestBinding)
	if err != nil {
		return store.Secret{}, applicationSecretMutationError(err)
	}
	var current store.Secret
	if !prepared {
		current, err = a.secrets.be.Store.GetSecret(ctx, tenantID, name)
		action, expectedVersion, resultVersion, eventType := "rotate", 0, 1, projections.EventApplicationSecretRotated
		if errors.Is(err, store.ErrSecretNotFound) {
			action, eventType = "create", projections.EventApplicationSecretCreated
		} else if err != nil {
			return store.Secret{}, err
		} else {
			expectedVersion, resultVersion = current.Version, current.Version+1
		}
		commandKeyDigest, commandEvidence, commandErr := a.applicationSecretCommandEvidence(tenantID, idempotencyKey, canonicalApplicationSecretCommand{
			Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: tenantEpoch, Action: action,
			Name: name, Surface: "vault", ExpectedVersion: expectedVersion,
			ResultVersion: resultVersion, Value: plaintext,
		})
		if commandErr != nil {
			return store.Secret{}, commandErr
		}
		if commandKeyDigest != keyDigest {
			return store.Secret{}, errors.New("api: application-secret idempotency digest changed")
		}
		sealed, sealErr := a.secrets.seal(ctx, tenantID, plaintext, sealAAD(tenantID, name))
		if sealErr != nil {
			return store.Secret{}, sealErr
		}
		payload = projections.ApplicationSecretMutation{
			TenantEpoch: tenantEpoch, Action: action, Name: name, ExpectedVersion: expectedVersion,
			ResultVersion: resultVersion, Sealed: sealed,
			IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
			CommandEvidence: commandEvidence, Surface: "vault",
		}
		fence, payload, err = a.claimApplicationSecretMutationFence(ctx, tenantID, name,
			operation, eventID, eventType, requestBinding, payload)
		if err != nil {
			return store.Secret{}, applicationSecretMutationError(err)
		}
	}
	if payload.Action == "create" {
		if fence.EventTime.IsZero() {
			fence, err = a.secrets.be.Store.FinalizeApplicationSecretMutationFence(
				ctx, tenantID, name, eventID, nil, time.Now().UTC())
			if err != nil {
				return store.Secret{}, applicationSecretMutationError(err)
			}
		}
		if _, _, err := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload, prepared); err != nil {
			return store.Secret{}, applicationSecretMutationError(err)
		}
		rec, getErr := a.secrets.be.Store.GetSecret(ctx, tenantID, name)
		if getErr != nil {
			return store.Secret{}, getErr
		}
		a.auditSecretVersion(ctx, tenantID, rec, nil)
		return rec, nil
	}
	if payload.Action != "rotate" {
		return store.Secret{}, fmt.Errorf("%w: Vault write fence action differs", store.ErrIdempotencyConflict)
	}
	if current.Name == "" {
		current, err = a.secrets.be.Store.GetSecret(ctx, tenantID, name)
		if err != nil {
			return store.Secret{}, err
		}
	}
	fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, tenantID, fence, payload)
	if err != nil {
		return store.Secret{}, applicationSecretMutationError(err)
	}
	event, canonical, err := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload, prepared)
	if err != nil {
		return store.Secret{}, applicationSecretMutationError(err)
	}
	rec := applicationSecretResultMeta(current, event, canonical)
	a.auditSecretVersion(ctx, tenantID, rec, nil)
	return rec, nil
}

func (a *API) vaultKVRead(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	name := strings.Trim(r.PathValue("name"), "/")
	if name == "" {
		writeVaultError(w, http.StatusBadRequest, "secret path is required")
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
	value, err := a.secrets.open(r.Context(), tenantID, rec.Sealed, sealAAD(tenantID, name))
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(value)
	a.writeVaultKVRead(w, rec, value)
}

func (a *API) writeVaultKVRead(w http.ResponseWriter, rec store.Secret, value []byte) {
	meta := vaultKVMetadata{
		CreatedTime:  rec.UpdatedAt.UTC().Format(time.RFC3339Nano),
		DeletionTime: "",
		Destroyed:    false,
		Version:      rec.Version,
		Custom:       nil,
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(metaJSON)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"request_id":"` + vaultCompatRequestID + `","lease_id":"","renewable":false,"lease_duration":0,"data":{"data":`))
	if rawJSONObject(value) {
		_, _ = w.Write(value)
	} else {
		quoted := appendJSONQuotedBytes([]byte(`{"value":`), value)
		quoted = append(quoted, '}')
		_, _ = w.Write(quoted)
		secret.Wipe(quoted)
	}
	_, _ = w.Write([]byte(`,"metadata":`))
	_, _ = w.Write(metaJSON)
	_, _ = w.Write([]byte(`},"warnings":null}`))
}

type vaultPKIIssueRequest struct {
	CommonName string `json:"common_name"`
	TTL        string `json:"ttl"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type vaultPKIIssueData struct {
	SerialNumber string          `json:"serial_number"`
	Certificate  secretJSONBytes `json:"certificate"`
	PrivateKey   secretJSONBytes `json:"private_key,omitempty"`
}

type vaultPKIIssueResponse struct {
	RequestID     string            `json:"request_id"`
	LeaseID       string            `json:"lease_id"`
	Renewable     bool              `json:"renewable"`
	LeaseDuration int               `json:"lease_duration"`
	Data          vaultPKIIssueData `json:"data"`
	Warnings      any               `json:"warnings"`
}

func (r vaultPKIIssueResponse) wipeSecrets() {
	r.Data.Certificate.wipe()
	r.Data.PrivateKey.wipe()
}

//trstctl:mutation
func (a *API) vaultPKIIssue(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	caCertDER, caSigner := a.secrets.resolveCA()
	if caSigner == nil || len(caCertDER) == 0 {
		writeVaultError(w, http.StatusServiceUnavailable, "dynamic PKI secret issuance unavailable")
		return
	}
	idempotencyKey, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	binding, err := vaultPKIRequestBinding(r, body)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "cannot bind PKI request")
		return
	}
	a.mutateWithRecorder(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		var req vaultPKIIssueRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.CommonName = strings.TrimSpace(req.CommonName)
		if req.CommonName == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "common_name is required")
		}
		ttl, err := parseVaultTTL(req.TTL, req.TTLSeconds)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		provider := a.secrets.pkiProvider(tenantID, caCertDER, caSigner)
		if err := a.recordPKIServerSideKeygen(ctx, tenantID, req.CommonName, "vault_pki_issue"); err != nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, err.Error())
		}
		cred, err := provider.Generate(ctx, dynsecret.GenerateRequest{
			Role: req.CommonName,
			TTL:  ttl,
		})
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
		}
		certPEM, keyPEM := splitCertKeyPEM(cred.Secret)
		secret.Wipe(cred.Secret)
		resp := vaultPKIIssueResponse{
			RequestID:     vaultCompatRequestID,
			LeaseDuration: int(ttl.Seconds()),
			Data: vaultPKIIssueData{
				SerialNumber: cred.BackendRef,
				Certificate:  secretJSONBytes(certPEM),
				PrivateKey:   secretJSONBytes(keyPEM),
			},
			Warnings: nil,
		}
		a.auditSecret(ctx, "pkisecret.issued", tenantID, req.CommonName, 0)
		return http.StatusOK, resp, nil
	}, false)
}

type vaultPKISignRequest struct {
	CSR        string `json:"csr"`
	TTL        string `json:"ttl"`
	TTLSeconds int    `json:"ttl_seconds"`
}

//trstctl:mutation
func (a *API) vaultPKISign(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	caCertDER, caSigner := a.secrets.resolveCA()
	if caSigner == nil || len(caCertDER) == 0 {
		writeVaultError(w, http.StatusServiceUnavailable, "dynamic PKI secret issuance unavailable")
		return
	}
	idempotencyKey, ok := vaultMutationKey(w, r)
	if !ok {
		return
	}
	binding, err := vaultPKIRequestBinding(r, body)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "cannot bind PKI request")
		return
	}
	a.mutateWithRecorder(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		var req vaultPKISignRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(req.CSR) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "csr is required")
		}
		ttl, err := parseVaultTTL(req.TTL, req.TTLSeconds)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		csrDER, commonName, err := decodePKISecretCSR([]byte(strings.TrimSpace(req.CSR)))
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		provider := a.secrets.pkiProvider(tenantID, caCertDER, caSigner)
		cred, err := provider.GenerateFromCSR(ctx, csrDER, ttl)
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
		}
		certPEM, _ := splitCertKeyPEM(cred.Secret)
		secret.Wipe(cred.Secret)
		resp := vaultPKIIssueResponse{
			RequestID:     vaultCompatRequestID,
			LeaseDuration: int(ttl.Seconds()),
			Data: vaultPKIIssueData{
				SerialNumber: cred.BackendRef,
				Certificate:  secretJSONBytes(certPEM),
			},
			Warnings: nil,
		}
		a.auditSecret(ctx, "pkisecret.issued", tenantID, commonName, 0)
		return http.StatusOK, resp, nil
	}, false)
}

func vaultPKIRequestBinding(r *http.Request, body []byte) (string, error) {
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		return "", err
	}
	escapedPath := ""
	if r.URL != nil {
		escapedPath = r.URL.EscapedPath()
	}
	encoded, err := json.Marshal(struct {
		Domain      string `json:"domain"`
		Principal   string `json:"principal"`
		Method      string `json:"method"`
		EscapedPath string `json:"escaped_path"`
		BodySHA256  string `json:"body_sha256"`
	}{
		Domain:      "trstctl.api.vault-pki-request-binding.v1",
		Principal:   principal,
		Method:      r.Method,
		EscapedPath: escapedPath,
		BodySHA256:  crypto.SHA256Hex(body),
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}

func parseVaultTTL(raw string, seconds int) (time.Duration, error) {
	if raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return 0, fmt.Errorf("ttl must be a Go duration such as 1h")
		}
		if d <= 0 {
			return 0, fmt.Errorf("ttl must be positive")
		}
		return d, nil
	}
	if seconds > 0 {
		return time.Duration(seconds) * time.Second, nil
	}
	return time.Hour, nil
}

func (a *API) captureVaultBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		writeVaultError(w, http.StatusBadRequest, "request body is required")
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, defaultRESTJSONBodyLimit+1))
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "invalid request body")
		return nil, false
	}
	if int64(len(body)) > defaultRESTJSONBodyLimit {
		secret.Wipe(body)
		writeVaultError(w, http.StatusRequestEntityTooLarge, "JSON request body too large")
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, true
}

func vaultIdempotencyKey(r *http.Request) (string, error) {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return key, nil
	}
	return "", errors.New("vault: Idempotency-Key is required for mutations")
}

func vaultMutationKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key, err := vaultIdempotencyKey(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return "", false
	}
	return key, true
}

func rawJSONObject(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' || !json.Valid(raw) {
		return false
	}
	var obj map[string]json.RawMessage
	return json.Unmarshal(raw, &obj) == nil
}
