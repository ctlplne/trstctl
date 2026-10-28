// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
)

// Vault-path dynamic credentials over the native leases (A203). A stock Vault
// or OpenBao client reads database, AWS and Kubernetes credentials the way it
// reads them from those engines, and renews, looks up and revokes the lease
// through sys/leases. Every credential is a native lease: the same providers,
// outbox, sealed one-time credential, expiry worker and audit as
// /api/v1/secrets/leases; this file only maps the Vault paths and shapes.
//
// A tenant's providers appear at two kinds of mount: the engine paths database/,
// aws/ and kubernetes/, which find the one provider of that engine offering the
// role, and each provider's own ID, which names it directly when several offer
// the same role.

const (
	vaultDatabaseEngine   = "database"
	vaultAWSEngine        = "aws"
	vaultKubernetesEngine = "kubernetes"

	// vaultDefaultLeaseTTL is a lease's TTL when the request names none,
	// lowered to the provider's maximum.
	vaultDefaultLeaseTTL = time.Hour
	// vaultSyncRevokeWait bounds how long a synchronous revoke waits for the
	// provider to confirm removal through the outbox.
	vaultSyncRevokeWait = 30 * time.Second
	vaultLeasePoll      = 200 * time.Millisecond
)

// vaultDynamicEngines maps each Vault secrets engine to the provider types whose
// leases it serves. Other provider types keep the native lease API only.
var vaultDynamicEngines = map[string][]string{
	vaultDatabaseEngine:   {"postgresql", "mysql", "mongodb", "redis"},
	vaultAWSEngine:        {"aws-iam", "aws-sts"},
	vaultKubernetesEngine: {"kubernetes"},
}

func vaultEngineForProviderType(providerType string) string {
	for engine, types := range vaultDynamicEngines {
		if slices.Contains(types, providerType) {
			return engine
		}
	}
	return ""
}

var vaultCompatDynamicRoutes = []vaultCompatRoute{
	vaultDynamicCredsRoute(http.MethodGet, "creds", "vaultCompatDynamicCredsRead", "/v1/database/creds/readonly", ""),
	vaultDynamicCredsRoute(http.MethodPost, "creds", "vaultCompatDynamicCredsWrite", "/v1/kubernetes/creds/reader", `{"kubernetes_namespace":"apps","ttl":"1h"}`),
	vaultDynamicCredsRoute(http.MethodPut, "creds", "vaultCompatDynamicCredsWritePut", "/v1/kubernetes/creds/reader", `{"kubernetes_namespace":"apps","ttl":"1h"}`),
	vaultDynamicCredsRoute(http.MethodGet, "sts", "vaultCompatDynamicSTSRead", "/v1/aws/sts/deployer", ""),
	vaultDynamicCredsRoute(http.MethodPost, "sts", "vaultCompatDynamicSTSWrite", "/v1/aws/sts/deployer", `{"ttl":"1h"}`),
	vaultDynamicCredsRoute(http.MethodPut, "sts", "vaultCompatDynamicSTSWritePut", "/v1/aws/sts/deployer", `{"ttl":"1h"}`),
	vaultLeaseRoute(http.MethodPut, "/v1/sys/leases/lookup", "/v1/sys/leases/lookup", "vaultCompatLeaseLookup",
		"Look up a dynamic-credential lease's issue and expiry times", "200", authz.SecretsRead, false, "VaultLeaseLookupResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsRead, a.vaultLeaseLookup) }),
	vaultLeaseRoute(http.MethodPost, "/v1/sys/leases/lookup", "/v1/sys/leases/lookup", "vaultCompatLeaseLookupPost",
		"Look up a dynamic-credential lease's issue and expiry times", "200", authz.SecretsRead, false, "VaultLeaseLookupResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsRead, a.vaultLeaseLookup) }),
	vaultLeaseRoute(http.MethodPut, "/v1/sys/leases/renew", "/v1/sys/leases/renew", "vaultCompatLeaseRenew",
		"Renew a database dynamic-credential lease", "200", authz.SecretsWrite, true, "VaultLeaseRenewResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultLeaseRenew) }),
	vaultLeaseRoute(http.MethodPost, "/v1/sys/leases/renew", "/v1/sys/leases/renew", "vaultCompatLeaseRenewPost",
		"Renew a database dynamic-credential lease", "200", authz.SecretsWrite, true, "VaultLeaseRenewResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultLeaseRenew) }),
	vaultLeaseRoute(http.MethodPut, "/v1/sys/leases/renew/{lease_id...}", "/v1/sys/leases/renew/{lease_id}", "vaultCompatLeaseRenewByPath",
		"Renew a database dynamic-credential lease named in the path", "200", authz.SecretsWrite, true, "VaultLeaseRenewResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultLeaseRenew) }),
	vaultLeaseRoute(http.MethodPost, "/v1/sys/leases/renew/{lease_id...}", "/v1/sys/leases/renew/{lease_id}", "vaultCompatLeaseRenewByPathPost",
		"Renew a database dynamic-credential lease named in the path", "200", authz.SecretsWrite, true, "VaultLeaseRenewResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultLeaseRenew) }),
	vaultLeaseRoute(http.MethodPut, "/v1/sys/leases/revoke", "/v1/sys/leases/revoke", "vaultCompatLeaseRevoke",
		"Revoke a dynamic-credential lease and remove its credential at the provider", "204", authz.SecretsWrite, true, "VaultGenericResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultLeaseRevoke) }),
	vaultLeaseRoute(http.MethodPost, "/v1/sys/leases/revoke", "/v1/sys/leases/revoke", "vaultCompatLeaseRevokePost",
		"Revoke a dynamic-credential lease and remove its credential at the provider", "204", authz.SecretsWrite, true, "VaultGenericResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultLeaseRevoke) }),
	vaultLeaseRoute(http.MethodPut, "/v1/sys/leases/revoke/{lease_id...}", "/v1/sys/leases/revoke/{lease_id}", "vaultCompatLeaseRevokeByPath",
		"Revoke a dynamic-credential lease named in the path", "204", authz.SecretsWrite, true, "VaultGenericResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultLeaseRevoke) }),
	vaultLeaseRoute(http.MethodPost, "/v1/sys/leases/revoke/{lease_id...}", "/v1/sys/leases/revoke/{lease_id}", "vaultCompatLeaseRevokeByPathPost",
		"Revoke a dynamic-credential lease named in the path", "204", authz.SecretsWrite, true, "VaultGenericResponse",
		func(a *API) http.HandlerFunc { return a.vaultAuth(authz.SecretsWrite, a.vaultLeaseRevoke) }),
}

func vaultDynamicCredsRoute(method, kind, operationID, samplePath, sampleBody string) vaultCompatRoute {
	rt := vaultCompatRoute{
		method:            method,
		pattern:           "/v1/{mount}/" + kind + "/{role}",
		contractPath:      "/v1/{mount}/" + kind + "/{role}",
		samplePath:        samplePath,
		sampleBody:        sampleBody,
		operationID:       operationID,
		summary:           "Open a dynamic-credential lease through a Vault database, AWS or Kubernetes engine path",
		successCode:       "200",
		permission:        authz.SecretsWrite,
		tokenRequired:     true,
		mutation:          true,
		responseSchema:    "VaultDynamicCredentialResponse",
		sensitiveResponse: true,
	}
	if method != http.MethodGet {
		rt.requestSchema = "VaultDynamicCredentialRequest"
	}
	if kind == "sts" {
		rt.summary = "Open an AWS STS lease through a Vault aws/sts path"
		rt.handler = func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultDynamicSTS) }
	} else {
		rt.handler = func(a *API) http.HandlerFunc { return a.vaultAuth("", a.vaultDynamicCreds) }
	}
	return rt
}

func vaultLeaseRoute(method, pattern, contractPath, operationID, summary, successCode string, permission authz.Permission, mutation bool, responseSchema string, handler func(*API) http.HandlerFunc) vaultCompatRoute {
	sample := strings.Replace(contractPath, "{lease_id}", "database/creds/readonly/lease-00000000-0000-0000-0000-000000000000", 1)
	body := `{"lease_id":"database/creds/readonly/lease-00000000-0000-0000-0000-000000000000"}`
	if strings.Contains(contractPath, "{lease_id}") {
		body = `{}`
	}
	return vaultCompatRoute{
		method: method, pattern: pattern, contractPath: contractPath, samplePath: sample, sampleBody: body,
		operationID: operationID, summary: summary, successCode: successCode, permission: permission,
		tokenRequired: true, mutation: mutation, requestSchema: "VaultLeaseRequest", responseSchema: responseSchema,
		handler: handler,
	}
}

// vaultDynamicTarget is the provider a Vault creds path resolved to.
type vaultDynamicTarget struct {
	mount    string
	kind     string // creds or sts
	role     string
	engine   string
	provider dynamicSecretConfiguredProvider
}

// resolveVaultDynamicTarget maps {mount}/{kind}/{role} to one provider. found is
// false when the mount is no dynamic engine of this tenant, so the request
// belongs to the shim's other mounts; err is the Vault-shaped refusal for an
// engine that has no single provider for the role.
func (s *secretsService) resolveVaultDynamicTarget(tenantID, mount, kind, role string) (vaultDynamicTarget, bool, error) {
	providers := s.configuredDynamicSecretProviders(tenantID)
	target := vaultDynamicTarget{mount: mount, kind: kind, role: role}
	for _, provider := range providers {
		if provider.ID != mount {
			continue
		}
		target.engine = vaultEngineForProviderType(provider.Type)
		if target.engine == "" {
			return target, true, errStatus(http.StatusBadRequest, fmt.Sprintf("provider %s (%s) has no Vault engine shape; use /api/v1/secrets/leases", provider.ID, provider.Type))
		}
		if kind == "sts" && target.engine != vaultAWSEngine {
			return target, false, nil
		}
		if len(provider.AllowedRoles) > 0 && !slices.Contains(provider.AllowedRoles, role) {
			return target, true, errStatus(http.StatusBadRequest, "unknown role: "+role)
		}
		target.provider = provider
		return target, true, nil
	}
	types, engine := vaultDynamicEngines[mount]
	if !engine || (kind == "sts" && mount != vaultAWSEngine) {
		return target, false, nil
	}
	target.engine = mount
	var offered, matches []dynamicSecretConfiguredProvider
	for _, provider := range providers {
		if !slices.Contains(types, provider.Type) {
			continue
		}
		offered = append(offered, provider)
		if len(provider.AllowedRoles) == 0 || slices.Contains(provider.AllowedRoles, role) {
			matches = append(matches, provider)
		}
	}
	switch {
	case len(offered) == 0:
		return target, false, nil
	case len(matches) == 0:
		return target, true, errStatus(http.StatusBadRequest, "unknown role: "+role)
	case len(matches) > 1:
		ids := make([]string, 0, len(matches))
		for _, provider := range matches {
			ids = append(ids, provider.ID)
		}
		return target, true, errStatus(http.StatusBadRequest, fmt.Sprintf("role %s is offered by providers %s; read it at <provider>/%s/%s", role, strings.Join(ids, ", "), kind, role))
	}
	target.provider = matches[0]
	return target, true, nil
}

// vaultDynamicProviderScope is the non-secret attachment a provider reports for
// the Vault shapes: the Kubernetes namespace and token audience, and whether a
// role assumes a given AWS role ARN.
type vaultDynamicProviderScope interface {
	DynamicSecretKubernetesScope() (namespace, audience string)
	DynamicSecretBindsRole(role, binding string) bool
}

func (s *secretsService) vaultProviderScope(tenantID, providerID string) (vaultDynamicProviderScope, bool) {
	for _, provider := range s.dynamicProviders(tenantID) {
		if provider.Name() != providerID {
			continue
		}
		scope, ok := provider.(vaultDynamicProviderScope)
		return scope, ok
	}
	return nil, false
}

func (a *API) vaultDynamicCreds(w http.ResponseWriter, r *http.Request) {
	a.vaultDynamicCredential(w, r, "creds")
}

func (a *API) vaultDynamicSTS(w http.ResponseWriter, r *http.Request) {
	a.vaultDynamicCredential(w, r, "sts")
}

// vaultDynamicCredential opens one native lease for a Vault creds or sts path.
//
//trstctl:mutation
func (a *API) vaultDynamicCredential(w http.ResponseWriter, r *http.Request, kind string) {
	mount, role := r.PathValue("mount"), r.PathValue("role")
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	var target vaultDynamicTarget
	found := false
	var err error
	if a.secrets != nil {
		target, found, err = a.secrets.resolveVaultDynamicTarget(tenantID, mount, kind, role)
	}
	if !found {
		// Not a dynamic engine here: the path belongs to the shim's
		// per-token cubbyhole like any other /v1/{mount}/{path}.
		r.SetPathValue("path", kind+"/"+role)
		if r.Method == http.MethodGet {
			a.vaultCubbyholeReadOrList(w, r)
		} else {
			a.vaultCubbyholeWrite(w, r)
		}
		return
	}
	if !a.vaultAuthorizeOperation(w, r, authz.SecretsWrite) {
		return
	}
	if err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	switch {
	case target.engine == vaultDatabaseEngine && r.Method != http.MethodGet,
		target.engine == vaultKubernetesEngine && r.Method == http.MethodGet:
		writeVaultError(w, http.StatusMethodNotAllowed, "unsupported operation")
		return
	}
	params, err := vaultDynamicParams(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	scope, _ := a.secrets.vaultProviderScope(tenantID, target.provider.ID)
	ttl, err := vaultDynamicLeaseTTL(target, params, scope)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	req, err := normalizeDynamicLeaseIssueRequest(dynamicLeaseIssueRequest{
		Provider: target.provider.ID, Role: role, TTLSeconds: int(ttl / time.Second),
	})
	if err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	if err := validateDynamicLeaseProviderRequest(target.provider, req); err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	binding, err := dynamicLeaseIssueBinding(principal, req)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "cannot bind the lease request")
		return
	}
	idempotencyKey, ok := vaultLeaseCommandKey(w, r)
	if !ok {
		return
	}
	a.mutateSealedDynamicLease(vaultErrorShape{w}, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		var lease dynsecret.Lease
		var credential []byte
		if issuer, ok := engine.(boundDynamicLeaseIssuer); ok {
			lease, credential, err = issuer.IssueBound(ctx, req.Provider, req.Role, ttl, idempotencyKey, binding)
		} else {
			lease, credential, err = engine.Issue(ctx, req.Provider, req.Role, ttl, idempotencyKey)
		}
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		defer secret.Wipe(credential)
		data, err := vaultDynamicCredentialShape(target, scope, lease, credential)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, vaultDynamicCredentialResponse{
			RequestID:     vaultCompatRequestID,
			LeaseID:       vaultLeaseID(target, lease.ID),
			Renewable:     target.engine == vaultDatabaseEngine,
			LeaseDuration: vaultSecondsUntil(lease.ExpiresAt),
			Data:          data,
		}, nil
	})
}

// vaultAuthorizeOperation applies a native permission after the mount is known,
// as vaultMountedSign does: the outer vaultAuth has authenticated the request
// and applied its Vault ACL, rate limit and tenant cipher.
func (a *API) vaultAuthorizeOperation(w http.ResponseWriter, r *http.Request, permission authz.Permission) bool {
	principal, err := a.principal(r)
	if err != nil {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return false
	}
	target := authz.Scope{TenantID: principal.TenantID, Project: r.Header.Get("X-Project")}
	if !principal.Can(permission, target) {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return false
	}
	if err := a.checkABAC(r.Context(), r, principal, permission, target); err != nil {
		writeVaultError(w, vaultStatus(err), err.Error())
		return false
	}
	return true
}

// vaultDynamicParams reads a creds request's parameters: the query string of a
// read, the JSON body of a write. Values arrive as the stock CLI sends them,
// strings, or as JSON numbers and booleans.
func vaultDynamicParams(r *http.Request) (map[string]string, error) {
	params := map[string]string{}
	if r.Method == http.MethodGet {
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				params[key] = values[len(values)-1]
			}
		}
		return params, nil
	}
	if r.Body == nil {
		return params, nil
	}
	var raw map[string]any
	decoder := json.NewDecoder(io.LimitReader(r.Body, defaultRESTJSONBodyLimit))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return params, nil
		}
		return nil, errors.New("request body must be a JSON object")
	}
	for key, value := range raw {
		switch v := value.(type) {
		case string:
			params[key] = v
		case json.Number:
			params[key] = v.String()
		case bool:
			params[key] = strconv.FormatBool(v)
		case []any:
			parts := make([]string, 0, len(v))
			for _, item := range v {
				text, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("%s must be a string or a list of strings", key)
				}
				parts = append(parts, text)
			}
			params[key] = strings.Join(parts, ",")
		case nil:
		default:
			return nil, fmt.Errorf("%s must be a string, number or boolean", key)
		}
	}
	return params, nil
}

// vaultDynamicLeaseTTL checks the engine's parameters against the provider and
// returns the lease TTL: the request's ttl, else an hour lowered to the
// provider's maximum.
func vaultDynamicLeaseTTL(target vaultDynamicTarget, params map[string]string, scope vaultDynamicProviderScope) (time.Duration, error) {
	switch target.engine {
	case vaultAWSEngine:
		if params["role_session_name"] != "" {
			return 0, errors.New("role_session_name is not supported: trstctl names the session after the lease")
		}
		if params["mfa_code"] != "" {
			return 0, errors.New("mfa_code is not supported")
		}
		if arn := strings.TrimSpace(params["role_arn"]); arn != "" {
			if scope == nil || !scope.DynamicSecretBindsRole(target.role, arn) {
				return 0, fmt.Errorf("role_arn %s is not the role %s assumes", arn, target.role)
			}
		}
	case vaultKubernetesEngine:
		var namespace, audience string
		if scope != nil {
			namespace, audience = scope.DynamicSecretKubernetesScope()
		}
		if requested := strings.TrimSpace(params["kubernetes_namespace"]); requested != "" && requested != namespace {
			return 0, fmt.Errorf("kubernetes_namespace %s is not this role's namespace %s", requested, namespace)
		}
		if binding, _ := strconv.ParseBool(params["cluster_role_binding"]); binding {
			return 0, errors.New("cluster_role_binding is not supported: the role binds within its namespace")
		}
		if requested := strings.TrimSpace(params["audiences"]); requested != "" {
			for _, item := range strings.Split(requested, ",") {
				if strings.TrimSpace(item) != audience {
					return 0, fmt.Errorf("audiences must be this role's audience %s", audience)
				}
			}
		}
	}
	var ttl time.Duration
	if raw := strings.TrimSpace(params["ttl"]); raw != "" && target.engine != vaultDatabaseEngine {
		parsed, err := parseVaultSeconds(raw)
		if err != nil {
			return 0, fmt.Errorf("ttl: %w", err)
		}
		ttl = parsed
	}
	if ttl == 0 {
		ttl = vaultDefaultLeaseTTL
		if limit := time.Duration(target.provider.MaximumTTLSeconds) * time.Second; limit > 0 && limit < ttl {
			ttl = limit
		}
	}
	return ttl, nil
}

// parseVaultSeconds reads a Vault duration: whole seconds ("3600") or a Go
// duration ("1h", "90m").
func parseVaultSeconds(raw string) (time.Duration, error) {
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if seconds <= 0 || seconds > math.MaxInt32 {
			return 0, errors.New("must be a positive number of seconds")
		}
		return time.Duration(seconds) * time.Second, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, errors.New("must be seconds or a duration such as 1h")
	}
	return d.Truncate(time.Second), nil
}

type vaultDynamicCredentialData struct {
	Username                string          `json:"username,omitempty"`
	Password                secretJSONBytes `json:"password,omitempty"`
	AccessKey               string          `json:"access_key,omitempty"`
	SecretKey               secretJSONBytes `json:"secret_key,omitempty"`
	SessionToken            secretJSONBytes `json:"session_token,omitempty"`
	ARN                     string          `json:"arn,omitempty"`
	ServiceAccountName      string          `json:"service_account_name,omitempty"`
	ServiceAccountNamespace string          `json:"service_account_namespace,omitempty"`
	ServiceAccountToken     secretJSONBytes `json:"service_account_token,omitempty"`
}

type vaultDynamicCredentialResponse struct {
	RequestID     string                     `json:"request_id"`
	LeaseID       string                     `json:"lease_id"`
	Renewable     bool                       `json:"renewable"`
	LeaseDuration int                        `json:"lease_duration"`
	Data          vaultDynamicCredentialData `json:"data"`
	Warnings      []string                   `json:"warnings"`
}

func (r vaultDynamicCredentialResponse) wipeSecrets() {
	r.Data.Password.wipe()
	r.Data.SecretKey.wipe()
	r.Data.SessionToken.wipe()
	r.Data.ServiceAccountToken.wipe()
}

// vaultDynamicCredentialShape lays a lease's credential out as the engine's
// Vault response data. Every secret is a new slice the response wipes.
func vaultDynamicCredentialShape(target vaultDynamicTarget, scope vaultDynamicProviderScope, lease dynsecret.Lease, credential []byte) (vaultDynamicCredentialData, error) {
	switch target.engine {
	case vaultDatabaseEngine:
		user, password, err := dynsecret.SplitCredentialUserinfo(target.provider.Type, credential)
		if err != nil {
			return vaultDynamicCredentialData{}, err
		}
		return vaultDynamicCredentialData{Username: user, Password: secretJSONBytes(password)}, nil
	case vaultAWSEngine:
		var issued struct {
			AccessKeyID     string           `json:"access_key_id"`
			SecretAccessKey secret.JSONBytes `json:"secret_access_key"`
			SessionToken    secret.JSONBytes `json:"session_token"`
		}
		if err := json.Unmarshal(credential, &issued); err != nil || issued.AccessKeyID == "" || len(issued.SecretAccessKey) == 0 {
			secret.Wipe(issued.SecretAccessKey)
			secret.Wipe(issued.SessionToken)
			return vaultDynamicCredentialData{}, errors.New("the AWS lease credential is not an access key")
		}
		arn, _ := dynsecret.AWSSTSSessionARN(lease.BackendRef)
		return vaultDynamicCredentialData{
			AccessKey: issued.AccessKeyID, SecretKey: secretJSONBytes(issued.SecretAccessKey),
			SessionToken: secretJSONBytes(issued.SessionToken), ARN: arn,
		}, nil
	case vaultKubernetesEngine:
		name, ok := dynsecret.KubernetesServiceAccountName(lease.BackendRef)
		if !ok {
			return vaultDynamicCredentialData{}, errors.New("the Kubernetes lease names no ServiceAccount")
		}
		var namespace string
		if scope != nil {
			namespace, _ = scope.DynamicSecretKubernetesScope()
		}
		return vaultDynamicCredentialData{
			ServiceAccountName: name, ServiceAccountNamespace: namespace,
			ServiceAccountToken: secretJSONBytes(bytesClone(credential)),
		}, nil
	default:
		return vaultDynamicCredentialData{}, fmt.Errorf("provider type %s has no Vault engine shape", target.provider.Type)
	}
}

func bytesClone(b []byte) []byte { return append([]byte(nil), b...) }

// vaultLeaseID is the Vault lease ID of a native lease: the path it was read at
// plus the native lease ID, which sys/leases resolves back.
func vaultLeaseID(target vaultDynamicTarget, nativeID string) string {
	return target.mount + "/" + target.kind + "/" + target.role + "/" + nativeID
}

func vaultSecondsUntil(t time.Time) int {
	seconds := time.Until(t).Round(time.Second) / time.Second
	if seconds < 0 {
		return 0
	}
	return int(seconds)
}

// vaultLeaseRequest is the sys/leases body: lookup, renew and revoke each read
// lease_id (or take it from the path), renew its increment, revoke its sync.
type vaultLeaseRequest struct {
	LeaseID   string `json:"lease_id"`
	Increment any    `json:"increment"`
	Sync      any    `json:"sync"`
}

func readVaultLeaseRequest(r *http.Request) (vaultLeaseRequest, error) {
	var req vaultLeaseRequest
	if r.Body != nil {
		decoder := json.NewDecoder(io.LimitReader(r.Body, defaultRESTJSONBodyLimit))
		decoder.UseNumber()
		if err := decoder.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			return req, errors.New("request body must be a JSON object")
		}
	}
	if strings.TrimSpace(req.LeaseID) == "" {
		req.LeaseID = r.PathValue("lease_id")
	}
	req.LeaseID = strings.Trim(strings.TrimSpace(req.LeaseID), "/")
	if req.LeaseID == "" {
		return req, errors.New("lease_id must be specified")
	}
	return req, nil
}

// resolveVaultLease reads the native lease a Vault lease ID names, checking
// that the path part still names its provider and role. Any mismatch is
// "invalid lease", as Vault answers for a lease it does not hold.
func (a *API) resolveVaultLease(ctx context.Context, tenantID, leaseID string) (dynsecret.Lease, vaultDynamicTarget, error) {
	invalid := errStatus(http.StatusBadRequest, "invalid lease")
	parts := strings.Split(leaseID, "/")
	if len(parts) != 4 || (parts[1] != "creds" && parts[1] != "sts") || a.secrets == nil {
		return dynsecret.Lease{}, vaultDynamicTarget{}, invalid
	}
	engine, err := a.secrets.dynamicLeaseEngine(tenantID)
	if err != nil {
		return dynsecret.Lease{}, vaultDynamicTarget{}, err
	}
	lease, err := getDynamicLeaseContext(ctx, engine, parts[3])
	if err != nil {
		if errors.Is(err, dynsecret.ErrLeaseNotFound) {
			return dynsecret.Lease{}, vaultDynamicTarget{}, invalid
		}
		return dynsecret.Lease{}, vaultDynamicTarget{}, err
	}
	provider, found := a.secrets.configuredDynamicSecretProvider(tenantID, lease.Provider)
	if !found || lease.Role != parts[2] {
		return dynsecret.Lease{}, vaultDynamicTarget{}, invalid
	}
	target := vaultDynamicTarget{mount: parts[0], kind: parts[1], role: parts[2], engine: vaultEngineForProviderType(provider.Type), provider: provider}
	if target.engine == "" || (parts[0] != provider.ID && parts[0] != target.engine) || (parts[1] == "sts" && target.engine != vaultAWSEngine) {
		return dynsecret.Lease{}, vaultDynamicTarget{}, invalid
	}
	return lease, target, nil
}

func (a *API) vaultLeaseLookup(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	req, err := readVaultLeaseRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	lease, target, err := a.resolveVaultLease(r.Context(), tenantID, req.LeaseID)
	if err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	// Vault drops a lease when it is revoked or runs out.
	if lease.State != dynsecret.LeaseActive || !time.Now().Before(lease.ExpiresAt) {
		writeVaultError(w, http.StatusBadRequest, "invalid lease")
		return
	}
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
		"id":           req.LeaseID,
		"issue_time":   lease.IssuedAt.UTC().Format(time.RFC3339Nano),
		"expire_time":  lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"last_renewal": nil,
		"renewable":    target.engine == vaultDatabaseEngine,
		"ttl":          vaultSecondsUntil(lease.ExpiresAt),
	}))
}

// vaultLeaseRenew renews a database lease to now + increment (0 renews it by its
// original TTL). A renewal never shortens a lease and stops at the provider's
// original hard expiry, with a warning, as Vault caps a TTL at its max_ttl.
// AWS and Kubernetes leases are not renewable here: their native renewal mints a
// replacement credential, which a Vault renew response cannot carry.
//
//trstctl:mutation
func (a *API) vaultLeaseRenew(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	req, err := readVaultLeaseRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	increment, err := vaultIncrement(req.Increment)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	lease, target, err := a.resolveVaultLease(r.Context(), tenantID, req.LeaseID)
	if err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	if lease.State != dynsecret.LeaseActive || !time.Now().Before(lease.ExpiresAt) {
		writeVaultError(w, http.StatusBadRequest, "invalid lease")
		return
	}
	if target.engine != vaultDatabaseEngine {
		writeVaultError(w, http.StatusBadRequest, "lease is not renewable")
		return
	}
	if increment <= 0 {
		increment = lease.ExpiresAt.Sub(lease.IssuedAt)
	}
	want := time.Now().Add(increment)
	var warnings []string
	if !lease.HardExpiresAt.IsZero() && want.After(lease.HardExpiresAt) {
		want = lease.HardExpiresAt
		warnings = append(warnings, "the renewal is capped at the provider's maximum TTL; the lease ends at "+lease.HardExpiresAt.UTC().Format(time.RFC3339))
	}
	extend := want.Sub(lease.ExpiresAt).Truncate(time.Second)
	if extend < time.Second {
		// Already at or past the requested expiry.
		writeVaultJSON(w, http.StatusOK, vaultLeaseRenewResponse(req.LeaseID, lease.ExpiresAt, warnings))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	binding, err := dynamicLeaseMutationBinding("renew", principal, lease.ID, int(extend/time.Second))
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "cannot bind the lease request")
		return
	}
	idempotencyKey, ok := vaultLeaseCommandKey(w, r)
	if !ok {
		return
	}
	a.mutateDurableBound(vaultErrorShape{w}, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		var renewed dynsecret.Lease
		if renewer, ok := engine.(boundDynamicLeaseRenewer); ok {
			renewed, err = renewer.RenewBound(ctx, lease.ID, extend, idempotencyKey, binding)
		} else {
			renewed, err = engine.Renew(ctx, lease.ID, extend)
		}
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		return http.StatusOK, vaultLeaseRenewResponse(req.LeaseID, renewed.ExpiresAt, warnings), nil
	})
}

func vaultLeaseRenewResponse(leaseID string, expiresAt time.Time, warnings []string) vaultEnvelope {
	envelope := newVaultEnvelope(nil)
	envelope.LeaseID = leaseID
	envelope.Renewable = true
	envelope.LeaseDuration = vaultSecondsUntil(expiresAt)
	if len(warnings) > 0 {
		envelope.Warnings = warnings
	}
	return envelope
}

func vaultIncrement(raw any) (time.Duration, error) {
	switch v := raw.(type) {
	case nil:
		return 0, nil
	case json.Number:
		seconds, err := v.Int64()
		if err != nil || seconds < 0 || seconds > math.MaxInt32 {
			return 0, errors.New("increment must be a whole number of seconds")
		}
		return time.Duration(seconds) * time.Second, nil
	case string:
		if strings.TrimSpace(v) == "" || v == "0" {
			return 0, nil
		}
		d, err := parseVaultSeconds(strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("increment %w", err)
		}
		return d, nil
	default:
		return 0, errors.New("increment must be a number of seconds")
	}
}

// vaultLeaseRevoke revokes the native lease and removes the credential at the
// provider through the outbox. Synchronous revocation (Vault's default; the
// stock CLI's -sync) answers 204 only once the provider confirms removal and
// otherwise refuses, naming why; asynchronous revocation answers 202 at once,
// as Vault queues it, unless removal is already confirmed.
//
//trstctl:mutation
func (a *API) vaultLeaseRevoke(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	req, err := readVaultLeaseRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	sync := true
	switch v := req.Sync.(type) {
	case nil:
	case bool:
		sync = v
	case string:
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			writeVaultError(w, http.StatusBadRequest, "sync must be a boolean")
			return
		}
		sync = parsed
	default:
		writeVaultError(w, http.StatusBadRequest, "sync must be a boolean")
		return
	}
	lease, target, err := a.resolveVaultLease(r.Context(), tenantID, req.LeaseID)
	if err != nil {
		writeVaultError(w, vaultHTTPStatus(err), err.Error())
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	binding, err := dynamicLeaseMutationBinding("revoke", principal, lease.ID, 0)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "cannot bind the lease request")
		return
	}
	idempotencyKey, ok := vaultLeaseCommandKey(w, r)
	if !ok {
		return
	}
	a.mutateDurableBound(vaultErrorShape{w}, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		var revoked dynsecret.Lease
		if revoker, ok := engine.(boundDynamicLeaseRevoker); ok {
			revoked, err = revoker.RevokeBound(ctx, lease.ID, idempotencyKey, binding)
		} else if err = engine.Revoke(ctx, lease.ID); err == nil {
			revoked, err = getDynamicLeaseContext(ctx, engine, lease.ID)
		}
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		if revoked.RevocationStatus == "completed" {
			return http.StatusNoContent, nil, nil
		}
		if !sync {
			envelope := newVaultEnvelope(nil)
			envelope.Warnings = []string{vaultPendingRemoval(target, revoked)}
			return http.StatusAccepted, envelope, nil
		}
		revoked, err = waitForVaultRemoval(ctx, engine, lease.ID)
		if err != nil {
			return 0, nil, err
		}
		if revoked.RevocationStatus == "completed" {
			return http.StatusNoContent, nil, nil
		}
		return 0, nil, errStatus(http.StatusConflict, vaultPendingRemoval(target, revoked))
	})
}

// waitForVaultRemoval polls the lease until the provider confirms or fails
// removal, or the synchronous wait ends.
func waitForVaultRemoval(ctx context.Context, engine dynsecret.Lifecycle, leaseID string) (dynsecret.Lease, error) {
	waitCtx, cancel := context.WithTimeout(ctx, vaultSyncRevokeWait)
	defer cancel()
	ticker := time.NewTicker(vaultLeasePoll)
	defer ticker.Stop()
	for {
		lease, err := getDynamicLeaseContext(waitCtx, engine, leaseID)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return getDynamicLeaseContext(ctx, engine, leaseID)
			}
			return dynsecret.Lease{}, err
		}
		if lease.RevocationStatus == "completed" || lease.RevocationStatus == "failed" {
			return lease, nil
		}
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return dynsecret.Lease{}, ctx.Err()
			}
			return lease, nil
		case <-ticker.C:
		}
	}
}

// vaultPendingRemoval says why a revoked lease's credential may still work.
func vaultPendingRemoval(target vaultDynamicTarget, lease dynsecret.Lease) string {
	if target.engine == vaultAWSEngine {
		until := "its native expiry"
		if expiry, ok := dynsecret.AWSSTSExpiration(lease.BackendRef); ok {
			until = expiry.UTC().Format(time.RFC3339)
		}
		return "the lease is revoked, but AWS cannot end an STS session early: the session stays valid until " + until
	}
	if lease.RevocationStatus == "failed" {
		return "the lease is revoked, but the provider did not confirm removal; revoke it again to retry"
	}
	return "the lease is revoked; the provider has not confirmed removal yet and it is retried until it completes"
}

// vaultLeaseCommandKey keys the Vault creds and sys/leases commands. An explicit
// Idempotency-Key replays as on every other route. Without one, each stock
// request is its own command: Vault opens a new lease on every creds read, and
// replaying the first would hand back a lease that may since have been revoked
// or run out; renew moves the expiry to an absolute target and never shortens
// it, and revoke is a state transition, so an unkeyed retry cannot double
// either effect.
func vaultLeaseCommandKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return key, true
	}
	nonce, err := crypto.RandomBytes(16)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "cannot key the lease command")
		return "", false
	}
	return "vault-lease-v1-" + hex.EncodeToString(nonce), true
}
