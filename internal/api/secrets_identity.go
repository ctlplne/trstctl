// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pkisecret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsdk"
	"trstctl.com/trstctl/internal/store"
)

// ---- one-time secret share + redeem (F60) ----------------------------------

type shareCreateRequest struct {
	Value      secretJSONBytes `json:"value"`
	TTLSeconds int             `json:"ttl_seconds"`
}

// shareCreateResponse returns the one-time bearer token (the share capability). The
// token travels out-of-band; it is delivered here exactly once and is NEVER written
// to the audit/event log (the GAP-001 fix audits a non-secret share id + a SHA-256 of
// the token instead).
type shareCreateResponse struct {
	Token     secretJSONBytes `json:"token"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// secretShareScope is the seal AAD scope binding a durable one-time share to its
// tenant, random share id, and token hash.
const secretShareScope = "secret-share"

func secretShareAAD(tenantID, shareID, tokenHash string) []byte {
	return []byte(tenantID + "/" + secretShareScope + "/" + shareID + "/" + tokenHash)
}

func secretApprovalResource(name string) string {
	return "secret:" + name
}

func isSecretApprovalAction(action string) bool {
	switch action {
	case "rotate", "recover", "delete":
		return true
	default:
		return false
	}
}

// createShare mints a durable one-time share. The token is returned to the caller
// once (the only bearer copy delivered out-of-band). PostgreSQL stores only
// SHA-256(token) plus sealed bytes, so the share survives an API restart without
// persisting the bearer token or plaintext. Idempotent (AN-5): a replay returns the
// same token from the original create result and does not mint a second share.
//
//trstctl:mutation
func (a *API) createShare(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req shareCreateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.Value) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "value is required")
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 24 * time.Hour
		}
		tokenRaw, err := crypto.RandomBytes(32)
		if err != nil {
			return 0, nil, err
		}
		defer secret.Wipe(tokenRaw)
		token := crypto.AppendHex(nil, tokenRaw)
		tokenHash := crypto.SHA256Hex(token)
		shareRaw, err := crypto.RandomBytes(16)
		if err != nil {
			req.Value.wipe()
			return 0, nil, err
		}
		shareID := hex.EncodeToString(shareRaw)
		secret.Wipe(shareRaw)
		sealed, err := a.secrets.seal(ctx, tenantID, []byte(req.Value), secretShareAAD(tenantID, shareID, tokenHash))
		req.Value.wipe()
		if err != nil {
			return 0, nil, err
		}
		expiresAt := time.Now().UTC().Add(ttl)
		if err := a.secrets.be.Store.PutSecretShare(ctx, tenantID, tokenHash, shareID, sealed, expiresAt); err != nil {
			return 0, nil, err
		}
		a.auditShare(ctx, "secret.shared", tenantID, shareID, tokenHash)
		return http.StatusCreated, shareCreateResponse{Token: secretJSONBytes(token), ExpiresAt: expiresAt}, nil
	})
}

type shareRedeemRequest struct {
	Token secretJSONBytes `json:"token"`
}

type shareRedeemResponse struct {
	Value secretJSONBytes `json:"value"`
}

// redeemShare consumes a one-time share token, returning the secret exactly once. A
// second redeem (or an expired/invalid token) fails. Consumption is a store-level
// DELETE ... RETURNING, so the single-use property holds across API restarts and
// concurrent served workers.
//
//trstctl:mutation
func (a *API) redeemShare(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req shareRedeemRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.Token) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "token is required")
		}
		defer req.Token.wipe()
		tokenHash := crypto.SHA256Hex([]byte(req.Token))
		share, err := a.secrets.be.Store.ConsumeSecretShare(ctx, tenantID, tokenHash, time.Now())
		if err != nil {
			if errors.Is(err, store.ErrSecretShareNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "share not found or already consumed")
			}
			return 0, nil, err
		}
		value, err := a.secrets.open(ctx, tenantID, share.Sealed, secretShareAAD(tenantID, share.ShareID, share.TokenHash))
		if err != nil {
			return 0, nil, err
		}
		a.auditShare(ctx, "secret.share.viewed", tenantID, share.ShareID, share.TokenHash)
		resp := shareRedeemResponse{Value: secretJSONBytes(value)}
		return http.StatusOK, resp, nil
	})
}

// approveSecretChange records a distinct approver for a pending sensitive
// secret-store mutation. It reuses the same tenant-scoped approval store and
// requester/approver separation as identity issuance approvals.
//
//trstctl:mutation
func (a *API) approveSecretChange(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.approvals == nil {
			return 0, nil, errStatus(http.StatusNotImplemented, "dual-control approval is not enabled on this deployment")
		}
		var req approvalRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if !isSecretApprovalAction(req.Action) {
			return 0, nil, errStatus(http.StatusBadRequest, `action must be "rotate", "recover", or "delete"`)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated approver is required")
		}
		resource := secretApprovalResource(name)
		count, err := a.approvals.RecordApproval(ctx, tenantID, resource, req.Action, principal.Subject)
		if err != nil {
			if errors.Is(err, store.ErrSelfIssuanceApproval) {
				return 0, nil, errStatus(http.StatusForbidden, "the requester cannot approve their own secret change")
			}
			if errors.Is(err, store.ErrAnonymousIssuanceApproval) {
				return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated approver is required")
			}
			return 0, nil, err
		}
		return http.StatusOK, approvalResponse{Resource: resource, Action: req.Action, Approver: principal.Subject, Approvals: count}, nil
	})
}

// ---- dynamic PKI secret (pkisecret, F67) -----------------------------------

type pkiSecretRequest struct {
	CommonName string `json:"common_name"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// pkiSecretResponse returns the dynamic PKI secret: the leaf certificate AND its
// matching private key (the GAP-004 fix — a bare cert is unusable). Returned only
// here, to the authorized caller; the key never leaves the boundary in a log/event
// (AN-8).
type pkiSecretResponse struct {
	Serial      string          `json:"serial"`
	CommonName  string          `json:"common_name"`
	Certificate secretJSONBytes `json:"certificate"` // leaf cert PEM
	PrivateKey  secretJSONBytes `json:"private_key"` // leaf private key PEM (PKCS#8)
}

// issuePKISecret issues a short-lived certificate + key as a dynamic secret (F67),
// through the issuing CA in the signer (AN-3/AN-4). The serial is recorded on the
// served revocation pipeline (GAP-005). Idempotent (AN-5).
//
//trstctl:mutation
func (a *API) issuePKISecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	caCertDER, caSigner := a.secrets.resolveCA()
	if caSigner == nil || len(caCertDER) == 0 {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "dynamic PKI secret issuance unavailable — no issuing CA"))
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req pkiSecretRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.CommonName == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "common_name is required")
		}
		provider := a.secrets.pkiProvider(tenantID, caCertDER, caSigner)
		cred, err := provider.Generate(ctx, dynsecret.GenerateRequest{
			Role: req.CommonName,
			TTL:  time.Duration(req.TTLSeconds) * time.Second,
		})
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
		}
		certPEM, keyPEM := splitCertKeyPEM(cred.Secret)
		resp := pkiSecretResponse{
			Serial: cred.BackendRef, CommonName: req.CommonName,
			Certificate: secretJSONBytes(certPEM), PrivateKey: secretJSONBytes(keyPEM),
		}
		secret.Wipe(cred.Secret) // cert/key PEM bytes now live only in resp until JSON encoding finishes
		a.auditSecret(ctx, "pkisecret.issued", tenantID, req.CommonName, 0)
		return http.StatusCreated, resp, nil
	})
}

// ---- machine login (authmethod, F58) ---------------------------------------

type machineLoginRequest struct {
	Method     string          `json:"method"`
	Credential secretJSONBytes `json:"credential"`
}

// machineLoginResponse is the scoped session the framework yields. It carries no
// secret — the credential is never echoed.
type machineLoginResponse struct {
	SessionID string    `json:"session_id"`
	Principal string    `json:"principal"`
	Method    string    `json:"method"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
}

// machineLogin authenticates a workload credential via the authmethod framework (F58)
// and returns a scoped, audited, tenant-scoped session. This route is PUBLIC (it is
// the entry point for an unauthenticated workload), so it carries no RBAC permission;
// the credential itself authenticates. X-Tenant-ID is only a lookup hint for the
// tenant-scoped method; token credentials MAC-bind the tenant and this handler
// rejects any header/credential mismatch (WIRE-002, AN-1).
func (a *API) machineLogin(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "X-Tenant-ID is required for machine login"))
		return
	}
	var req machineLoginRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	method := req.Method
	if method == "" {
		method = "token"
	}
	mgr, err := a.secrets.authManager(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, errMachineLoginNotConfigured) {
			a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "machine login is not configured"))
			return
		}
		a.writeError(w, err)
		return
	}
	sess, err := mgr.Login(r.Context(), method, []byte(req.Credential))
	req.Credential.wipe() // the credential is consumed; wipe our copy (AN-8)
	if err != nil {
		// Do not echo the credential or the reason beyond "unauthorized".
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "machine login failed"))
		return
	}
	if sess.TenantID != tenantID {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "machine login failed"))
		return
	}
	// C-S3 (DA-02): the issued session becomes ledger state. When the ledger
	// subsystem is configured, a session that cannot be recorded is not
	// issued — evidence-first, matching the PAM precedent (AN-2).
	if err := a.recordMachineSession(r.Context(), tenantID, sess); err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, machineLoginResponse{
		SessionID: sess.ID, Principal: sess.Principal, Method: sess.Method,
		Scopes: sess.Scopes, ExpiresAt: sess.ExpiresAt,
	})
}

var errMachineLoginNotConfigured = errors.New("machine login is not configured")

/* ---- machine auth-method projection (C-S2, DA-02) ------------------------ */

// machineAuthMethodInfo is the allow-listed, secret-free projection of one
// configured machine-login method. Fields are hand-copied per concrete type —
// never json.Marshal a raw authmethod.Method: several carry secret-shaped
// material (TokenMethod.Secret, verification JWKS) that must not cross the API
// boundary (AN-8). JWKS presence is projected as a boolean only.
type machineAuthMethodInfo struct {
	Name                   string              `json:"name"`
	Type                   string              `json:"type"`
	Source                 string              `json:"source"`
	Issuer                 string              `json:"issuer,omitempty"`
	Audience               string              `json:"audience,omitempty"`
	TenantClaim            string              `json:"tenant_claim,omitempty"`
	SubjectClaim           string              `json:"subject_claim,omitempty"`
	ScopesClaim            string              `json:"scopes_claim,omitempty"`
	PrincipalPrefix        string              `json:"principal_prefix,omitempty"`
	Scopes                 []string            `json:"scopes,omitempty"`
	ScopesByPrincipal      map[string][]string `json:"scopes_by_principal,omitempty"`
	AllowedNamespaces      []string            `json:"allowed_namespaces,omitempty"`
	AllowedServiceAccounts []string            `json:"allowed_service_accounts,omitempty"`
	AllowedProjects        []string            `json:"allowed_projects,omitempty"`
	AllowedAzureTenants    []string            `json:"allowed_azure_tenants,omitempty"`
	AllowedAccounts        []string            `json:"allowed_accounts,omitempty"`
	AllowedARNs            []string            `json:"allowed_arns,omitempty"`
	RequiredClaims         map[string]string   `json:"required_claims,omitempty"`
	JWKSConfigured         bool                `json:"jwks_configured"`
	AllowUnexpiring        bool                `json:"allow_unexpiring,omitempty"`
	// Disabled reflects the event-sourced per-tenant overlay (C-S3): a
	// disabled method is refused by the login exchange until re-enabled.
	Disabled bool `json:"disabled,omitempty"`
}

func sortedBoolKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func copyScopesByPrincipal(m map[string][]string) map[string][]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string][]string, len(m))
	for principal, scopes := range m {
		out[principal] = append([]string(nil), scopes...)
	}
	return out
}

func copyRequiredClaims(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// machineAuthMethodProjection allow-lists the non-secret configuration of one
// concrete method. Unknown method types degrade to name/type only rather than
// risking reflection over unvetted fields.
func machineAuthMethodProjection(m authmethod.Method, source string) machineAuthMethodInfo {
	info := machineAuthMethodInfo{Name: m.Name(), Type: m.Name(), Source: source}
	switch v := m.(type) {
	case authmethod.TokenMethod:
		info.Type = "token"
		info.Audience = v.Audience
		info.AllowUnexpiring = v.AllowUnexpiring
		info.ScopesByPrincipal = copyScopesByPrincipal(v.Scopes)
	case authmethod.OIDCMethod:
		info.Type = "oidc"
		info.Issuer = v.Issuer
		info.Audience = v.Audience
		info.TenantClaim = v.TenantClaim
		info.PrincipalPrefix = v.PrincipalPrefix
		info.RequiredClaims = copyRequiredClaims(v.RequiredClaims)
		info.JWKSConfigured = len(v.JWKS.Keys) > 0
	case authmethod.JWTMethod:
		info.Type = "jwt"
		info.Issuer = v.Issuer
		info.Audience = v.Audience
		info.TenantClaim = v.TenantClaim
		info.SubjectClaim = v.SubjectClaim
		info.ScopesClaim = v.ScopesClaim
		info.PrincipalPrefix = v.PrincipalPrefix
		info.Scopes = append([]string(nil), v.Scopes...)
		info.RequiredClaims = copyRequiredClaims(v.RequiredClaims)
		info.JWKSConfigured = len(v.JWKS.Keys) > 0
	case authmethod.KubernetesSATMethod:
		info.Type = "kubernetes"
		info.Issuer = v.Issuer
		info.Audience = v.Audience
		info.TenantClaim = v.TenantClaim
		info.AllowedNamespaces = sortedBoolKeys(v.AllowedNamespaces)
		info.AllowedServiceAccounts = sortedBoolKeys(v.AllowedServiceAccounts)
		info.Scopes = append([]string(nil), v.Scopes...)
		info.JWKSConfigured = len(v.JWKS.Keys) > 0
	case authmethod.GCPMethod:
		info.Type = "gcp"
		info.Issuer = v.Issuer
		info.Audience = v.Audience
		info.TenantClaim = v.TenantClaim
		info.AllowedProjects = sortedBoolKeys(v.AllowedProjects)
		info.Scopes = append([]string(nil), v.Scopes...)
		info.JWKSConfigured = len(v.JWKS.Keys) > 0
	case authmethod.AzureMethod:
		info.Type = "azure"
		info.Issuer = v.Issuer
		info.Audience = v.Audience
		info.TenantClaim = v.TenantClaim
		info.SubjectClaim = v.PrincipalClaim
		info.AllowedAzureTenants = sortedBoolKeys(v.AllowedAzureTenants)
		info.Scopes = append([]string(nil), v.Scopes...)
		info.JWKSConfigured = len(v.JWKS.Keys) > 0
	case authmethod.AWSIAMMethod:
		info.Type = "aws-iam"
		info.AllowedAccounts = sortedBoolKeys(v.AllowedAccounts)
		info.AllowedARNs = sortedBoolKeys(v.AllowedARNs)
		info.Scopes = append([]string(nil), v.Scopes...)
	}
	return info
}

// listMachineAuthMethods serves GET /api/v1/secrets/auth-methods (C-S2,
// DA-02): a read-only, tenant-scoped projection of exactly the method set the
// machine-login exchange composes in authManager — the builtin token method
// (when AuthSecret is configured) plus the per-tenant config factory. Methods
// remain declared in server config; this endpoint projects, it does not edit.
func (a *API) listMachineAuthMethods(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	disabled := map[string]bool{}
	if a.secrets.be.Store != nil {
		overlay, err := a.secrets.be.Store.DisabledMachineAuthMethods(r.Context(), tenantID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		disabled = overlay
	}
	items := make([]machineAuthMethodInfo, 0, 4)
	if len(a.secrets.be.AuthSecret) > 0 {
		// The builtin exchange is projected without constructing a TokenMethod:
		// its only interesting fields here are name/type, and its Secret must
		// never travel toward a response writer.
		items = append(items, machineAuthMethodInfo{Name: "token", Type: "token", Source: "builtin", Disabled: disabled["token"]})
	}
	if a.secrets.be.MachineAuthMethods != nil {
		for _, m := range a.secrets.be.MachineAuthMethods(tenantID) {
			if m == nil {
				continue
			}
			info := machineAuthMethodProjection(m, "config")
			info.Disabled = disabled[info.Name]
			items = append(items, info)
		}
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

/* ---- machine session ledger + method overlay (C-S3, DA-02) ---------------- */

// machineSessionInfo is the ledger row served to the console. "expired" is a
// display status computed from expires_at; the projection stores only
// active/revoked so the ledger needs no expiry worker.
type machineSessionInfo struct {
	ID        string     `json:"id"`
	Principal string     `json:"principal"`
	Method    string     `json:"method"`
	Scopes    []string   `json:"scopes,omitempty"`
	Status    string     `json:"status"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty"`
}

func machineSessionDisplay(m store.MachineSession, now time.Time) machineSessionInfo {
	status := m.Status
	if status == store.MachineSessionStatusActive && now.After(m.ExpiresAt) {
		status = "expired"
	}
	return machineSessionInfo{
		ID: m.ID, Principal: m.Principal, Method: m.Method, Scopes: m.Scopes,
		Status: status, IssuedAt: m.IssuedAt, ExpiresAt: m.ExpiresAt,
		RevokedAt: m.RevokedAt, RevokedBy: m.RevokedBy,
	}
}

func machineSessionLedgerDisabledProblem() *problem.Problem {
	return problem.New(http.StatusNotFound, "machine session ledger requires the event log and datastore")
}

// machineSessionLedgerReady reports whether the event-sourced ledger can be
// served: it needs both the event log (append) and the store (projection).
func (a *API) machineSessionLedgerReady() bool {
	return a.secrets != nil && a.secrets.be.Store != nil && a.log != nil
}

// recordMachineSession appends secrets.session.started and projects it (AN-2).
// When the ledger subsystem is not configured (no event log or store), the
// exchange behaves as before C-S3: the session is a scope receipt only, and
// GET /secrets/sessions says so honestly instead of serving an empty ledger.
func (a *API) recordMachineSession(ctx context.Context, tenantID string, sess authmethod.Session) error {
	if !a.machineSessionLedgerReady() {
		return nil
	}
	payload, err := json.Marshal(projections.MachineSessionStarted{
		ID: sess.ID, Principal: sess.Principal, Method: sess.Method,
		Scopes: sess.Scopes, IssuedAt: sess.IssuedAt, ExpiresAt: sess.ExpiresAt,
	})
	if err != nil {
		return err
	}
	ev, err := a.log.Append(ctx, events.Event{Type: projections.EventMachineSessionStarted, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}
	return projections.New(a.secrets.be.Store).Apply(ctx, ev)
}

// listMachineSessions serves GET /api/v1/secrets/sessions (C-S3, DA-02): the
// issued-session ledger, newest first. Sessions are advisory scope receipts —
// the response never carries credential material.
func (a *API) listMachineSessions(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	if !a.machineSessionLedgerReady() {
		a.writeProblem(w, machineSessionLedgerDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be an integer"))
			return
		}
		limit = parsed
	}
	sessions, err := a.secrets.be.Store.ListMachineSessions(r.Context(), tenantID, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	items := make([]machineSessionInfo, 0, len(sessions))
	for _, m := range sessions {
		items = append(items, machineSessionDisplay(m, now))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

// revokeMachineSession serves POST /api/v1/secrets/sessions/{id}/revoke
// (C-S3): an idempotent, event-sourced ledger revocation. Machine sessions
// are not consumed by later API calls, so this marks evidence state — the
// enforcement half of revocation is the auth-method overlay (refuse new
// logins) and API-token revocation.
//
//trstctl:mutation
func (a *API) revokeMachineSession(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	if !a.machineSessionLedgerReady() {
		a.writeProblem(w, machineSessionLedgerDisabledProblem())
		return
	}
	id := r.PathValue("id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if id == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "session id is required")
		}
		if _, err := a.secrets.be.Store.GetMachineSession(ctx, tenantID, id); err != nil {
			return 0, nil, errStatus(http.StatusNotFound, "machine session not found")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		payload, err := json.Marshal(projections.MachineSessionRevoked{ID: id, RevokedBy: principal.Subject, RevokedAt: time.Now().UTC()})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.log.Append(ctx, events.Event{Type: projections.EventMachineSessionRevoked, TenantID: tenantID, Data: payload})
		if err != nil {
			return 0, nil, err
		}
		if err := projections.New(a.secrets.be.Store).Apply(ctx, ev); err != nil {
			return 0, nil, err
		}
		updated, err := a.secrets.be.Store.GetMachineSession(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, machineSessionDisplay(updated, time.Now().UTC()), nil
	})
}

// machineAuthMethodOverrideResponse acknowledges a disable/enable overlay
// change.
type machineAuthMethodOverrideResponse struct {
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
}

// setMachineAuthMethodOverride is the shared disable/enable implementation:
// validate the method exists on the served projection, then append the
// overlay event and project it (AN-2). The login exchange consults the
// overlay on every login, so a disabled method is refused immediately.
func (a *API) setMachineAuthMethodOverride(w http.ResponseWriter, r *http.Request, idempotencyKey string, disable bool) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	if !a.machineSessionLedgerReady() {
		a.writeProblem(w, machineSessionLedgerDisabledProblem())
		return
	}
	name := r.PathValue("name")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if name == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "method name is required")
		}
		known := map[string]bool{}
		if len(a.secrets.be.AuthSecret) > 0 {
			known["token"] = true
		}
		if a.secrets.be.MachineAuthMethods != nil {
			for _, m := range a.secrets.be.MachineAuthMethods(tenantID) {
				if m != nil {
					known[m.Name()] = true
				}
			}
		}
		if !known[name] {
			return 0, nil, errStatus(http.StatusNotFound, "no such configured machine-auth method")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		eventType := projections.EventMachineAuthMethodEnabled
		if disable {
			eventType = projections.EventMachineAuthMethodDisabled
		}
		payload, err := json.Marshal(projections.MachineAuthMethodOverride{Name: name, UpdatedBy: principal.Subject})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
		if err != nil {
			return 0, nil, err
		}
		if err := projections.New(a.secrets.be.Store).Apply(ctx, ev); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, machineAuthMethodOverrideResponse{Name: name, Disabled: disable}, nil
	})
}

// disableMachineAuthMethod serves POST /api/v1/secrets/auth-methods/{name}/disable.
//
//trstctl:mutation
func (a *API) disableMachineAuthMethod(w http.ResponseWriter, r *http.Request) {
	a.setMachineAuthMethodOverride(w, r, r.Header.Get("Idempotency-Key"), true)
}

// enableMachineAuthMethod serves POST /api/v1/secrets/auth-methods/{name}/enable.
//
//trstctl:mutation
func (a *API) enableMachineAuthMethod(w http.ResponseWriter, r *http.Request) {
	a.setMachineAuthMethodOverride(w, r, r.Header.Get("Idempotency-Key"), false)
}

// ---- per-request framework construction (tenant-scoped, AN-1) --------------

// secretFetcher returns a secretsdk.Fetcher that unseals the tenant's stored secret
// by name. It is the SDK's tenant-scoped lease engine for the served read (F64): a
// revoked/absent secret surfaces as an error here, which the SDK turns into a
// fail-safe miss.
func (s *secretsService) secretFetcher(tenantID string) secretsdk.Fetcher {
	return fetcherFunc(func(ctx context.Context, path string) ([]byte, time.Time, error) {
		rec, err := s.be.Store.GetSecret(ctx, tenantID, path)
		if err != nil {
			return nil, time.Time{}, err
		}
		plain, err := s.open(ctx, tenantID, rec.Sealed, sealAAD(tenantID, path))
		if err != nil {
			return nil, time.Time{}, err
		}
		// A stored application secret has no intrinsic expiry; give the SDK a short
		// freshness window so it re-fetches (and re-checks existence) promptly.
		return plain, time.Now().Add(30 * time.Second), nil
	})
}

// fetcherFunc adapts a func to secretsdk.Fetcher.
type fetcherFunc func(ctx context.Context, path string) ([]byte, time.Time, error)

// resolveCA returns the issuing CA cert DER and signer, or (nil, nil) when no CA is
// provisioned (the dynamic PKI secret is then unavailable, fail closed).
func (s *secretsService) resolveCA() ([]byte, crypto.DigestSigner) {
	if s.be.CA == nil {
		return nil, nil
	}
	return s.be.CA()
}

// pkiProvider builds a per-tenant PKIProvider over the issuing CA, wiring the
// revocation sink so issuance/revocation are recorded on the served pipeline
// (GAP-005). The leaf key is generated AND returned by Generate (GAP-004).
func (s *secretsService) pkiProvider(tenantID string, caCertDER []byte, caSigner crypto.DigestSigner) *pkisecret.PKIProvider {
	profile := pkisecret.Profile{Name: "secrets-api", MaxTTL: 30 * 24 * time.Hour}
	var opts []pkisecret.Option
	if s.be.RevocationSink != nil {
		opts = append(opts, pkisecret.WithRevocationSink(tenantID, s.be.CAID, s.be.RevocationSink))
	}
	return pkisecret.NewPKIProvider(caCertDER, caSigner, profile, nil, opts...)
}

// authManager builds a per-tenant authmethod.Manager with the configured machine
// login methods (F58). Each method is tenant-scoped at construction so a session is
// bound to this tenant (AN-1).
func (s *secretsService) authManager(ctx context.Context, tenantID string) (*authmethod.Manager, error) {
	ttl := s.be.SessionTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	methods := make([]authmethod.Method, 0, 1)
	if len(s.be.AuthSecret) > 0 {
		methods = append(methods, authmethod.TokenMethod{Secret: s.be.AuthSecret, TenantID: tenantID})
	}
	if s.be.MachineAuthMethods != nil {
		methods = append(methods, s.be.MachineAuthMethods(tenantID)...)
	}
	// C-S3 (DA-02): the event-sourced per-tenant disable overlay is enforced
	// here, at the exchange itself. Overlay read errors fail closed — refusing
	// logins beats accepting a credential against a disabled method.
	if s.be.Store != nil {
		disabled, err := s.be.Store.DisabledMachineAuthMethods(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if len(disabled) > 0 {
			kept := methods[:0]
			for _, m := range methods {
				if !disabled[m.Name()] {
					kept = append(kept, m)
				}
			}
			methods = kept
		}
	}
	if len(methods) == 0 {
		return nil, errMachineLoginNotConfigured
	}
	return authmethod.New(authmethod.Config{
		TenantID: tenantID,
		Methods:  methods,
		Audit:    s.be.Audit,
		TTL:      ttl,
	})
}

func (a *API) requireSecretApproval(ctx context.Context, tenantID, name, action string) error {
	if !a.gate.RequireApproval {
		return nil
	}
	if a.gate.Checker == nil {
		return errStatus(http.StatusForbidden, "dual control required but no approval store is configured")
	}
	principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		return errStatus(http.StatusUnauthorized, "an authenticated requester is required")
	}
	approved, reason := a.gate.Checker.IsApproved(ctx, tenantID, secretApprovalResource(name), action, principal.Subject)
	if approved {
		return nil
	}
	if reason == "" {
		reason = "this secret change has not been approved by the required number of distinct approvers"
	}
	return errStatus(http.StatusForbidden, "dual control: "+reason)
}

// auditSecret records a secret/share/pki event (AN-2) carrying ONLY non-secret
// metadata (name/version) — never a value, key, or token (AN-8). Best-effort: a
// dropped audit increments the dropped-event counter (CODE-001) but does not fail the
// already-committed state change.
func (a *API) auditSecret(ctx context.Context, eventType, tenantID, name string, version int) {
	if a.secrets == nil || a.secrets.be.Audit == nil {
		return
	}
	payload, _ := json.Marshal(map[string]any{"name": name, "version": version})
	_ = auditsink.Emit(ctx, a.secrets.be.Audit, nil, eventType, tenantID, payload)
}

func (a *API) auditShare(ctx context.Context, eventType, tenantID, shareID, tokenHash string) {
	if a.secrets == nil || a.secrets.be.Audit == nil {
		return
	}
	payload, _ := json.Marshal(map[string]any{"share_id": shareID, "token_sha256": tokenHash})
	_ = auditsink.Emit(ctx, a.secrets.be.Audit, nil, eventType, tenantID, payload)
}

// auditSecretVersion records the sealed version-written event. The payload contains
// ciphertext only, never the plaintext value; it is what lets the version-history
// projection be rebuilt without exposing a secret (AN-2/AN-8).
func (a *API) auditSecretVersion(ctx context.Context, tenantID string, rec store.Secret, recoveredFrom *int) {
	if a.secrets == nil || a.secrets.be.Audit == nil {
		return
	}
	payload := map[string]any{"name": rec.Name, "version": rec.Version, "sealed": rec.Sealed, "written_at": rec.UpdatedAt}
	if recoveredFrom != nil {
		payload["recovered_from_version"] = *recoveredFrom
	}
	data, _ := json.Marshal(payload)
	_ = auditsink.Emit(ctx, a.secrets.be.Audit, nil, "secret.version.written", tenantID, data)
}

// secretsDisabledProblem is returned when the secrets surface was not wired
// (WithSecrets not given). It fails closed with a clear, non-leaking message.
func secretsDisabledProblem() *problem.Problem {
	return problem.New(http.StatusNotFound, "secrets surface is not enabled")
}

// splitCertKeyPEM splits a PEM bundle (CERTIFICATE block(s) then a PRIVATE KEY block)
// into the certificate PEM and the private key PEM. pkisecret returns the
// concatenation; the served response presents them as distinct fields.
func splitCertKeyPEM(bundle []byte) (certPEM, keyPEM []byte) {
	rest := bundle
	for {
		blk, tail := pem.Decode(rest)
		if blk == nil {
			break
		}
		encoded := pem.EncodeToMemory(blk)
		if blk.Type == "PRIVATE KEY" || blk.Type == "EC PRIVATE KEY" || blk.Type == "RSA PRIVATE KEY" {
			keyPEM = append(keyPEM, encoded...)
		} else {
			certPEM = append(certPEM, encoded...)
		}
		rest = tail
	}
	return certPEM, keyPEM
}
