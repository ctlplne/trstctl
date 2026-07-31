// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/leaseworker"
	"trstctl.com/trstctl/internal/pkisecret"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/secretsdk"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// This file is the SERVED secrets/identity surface (GAP-006 / EXC-WIRE secrets):
// it mounts the five previously library-only frameworks on the running binary's
// authenticated, tenant-scoped REST API:
//
//   - secretsdk + the secret store: CRUD + rotation of an application secret, sealed
//     at rest (internal/crypto/seal, AN-8) under RLS (AN-1), event-sourced (AN-2),
//     read through a secretsdk.Client so the served read path is the SDK's
//     fail-safe/caching fetch, not a bespoke query (F64).
//   - secretshare (F60): a durable one-time self-destructing share — create returns a
//     bearer token out-of-band; PostgreSQL stores only SHA-256(token) plus a sealed
//     payload; redeem returns the secret exactly once and deletes the row. Audit
//     events carry a non-secret share id + token hash, never the token itself.
//   - pkisecret (F67): a dynamic PKI secret — issue a short-lived cert AND its leaf
//     private key as a PEM bundle (the GAP-004 fix), recorded on the served
//     revocation pipeline (the GAP-005 RevocationSink) so a later revoke actually
//     stops it validating.
//   - authmethod (F58): the machine-login framework — a workload presents a token
//     credential and receives a scoped, audited, tenant-scoped session.
//
// Every value-returning route returns the secret ONLY to the authenticated,
// authorized caller as its design intends; nothing here logs a secret or puts it in
// an event payload (AN-8). Mutations run through the standard mutate() path, so they
// are idempotent (AN-5) and the tenant is the authenticated principal's, never a
// request header (AN-1).

// SecretsBackend is the dependency set the served secrets surface needs. The server
// builds it (wiring the KEK, store, event log, and the issuing CA signer) and hands
// it in via WithSecrets, so the api package owns the surface while the composition
// stays in internal/server.
type SecretsBackend struct {
	// TenantCrypto resolves the authenticated tenant's deployment or independent
	// key domain under the shared PostgreSQL fence. Production always wires it;
	// it is the wall that makes an opted-in tenant fail closed while sealed.
	TenantCrypto tenantseal.Access
	// KEK is the legacy embed/test fallback for compositions that do not serve
	// tenant key-domain lifecycle. The default binary never uses it directly for
	// tenant secret values because buildRunDeps always supplies TenantCrypto.
	KEK seal.KeyWrapper
	// Store is the relational backing for the secret store (sealed rows) and the
	// pkisecret revocation records, all under RLS (AN-1). Required.
	Store *store.Store
	// Audit records secret/share/login events to the AN-2 event log. A Nop is
	// acceptable for a bare embed; the served path wires the log-backed one.
	Audit auditsink.Auditor
	// CA resolves the issuing CA (its cert DER and the signer-backed DigestSigner whose
	// key lives in the out-of-process signer, AN-4) at request time, backing the
	// dynamic PKI secret. It is a resolver, not a value, because the control plane
	// provisions the CA AFTER the API is constructed; resolving lazily lets the secrets
	// surface be wired at API-build time and still reach the CA once it exists. When it
	// returns a nil signer (no CA provisioned), the pkisecret route reports issuance
	// unavailable (fail closed), matching the rest of the served issuance path. Nil
	// (the field itself) also means no dynamic PKI secret.
	CA func() (certDER []byte, signer crypto.DigestSigner)
	// RevocationSink records issued/revoked dynamic-secret serials on the served
	// revocation pipeline (store-backed CRL/OCSP + ca.certificate.revoked event), so a
	// revoked pkisecret cert stops validating (GAP-005). Optional; nil falls back to
	// pkisecret's in-memory liveness set.
	RevocationSink pkisecret.RevocationSink
	// CAID is the issuing CA id the revocation records are scoped under (AN-1).
	CAID string
	// AuthSecret is the HMAC key the served machine-login token method verifies
	// against (authmethod.TokenMethod). When empty, the login route reports the method
	// is not configured unless MachineAuthMethods contributes another method. It is
	// []byte and never logged (AN-8).
	AuthSecret []byte
	// MachineAuthMethods returns tenant-scoped workload login methods such as
	// Kubernetes SAT, AWS IAM, GCP, Azure, generic OIDC, and generic JWT. The factory
	// is called per request with the X-Tenant-ID lookup hint, and each returned method
	// must verify that tenant binding itself (AN-1).
	MachineAuthMethods func(tenantID string) []authmethod.Method
	// SessionTTL bounds a machine-login session; zero selects one hour.
	SessionTTL time.Duration
	// DynamicProviders are the configured dynamic-secret backends exposed by the
	// served lease API (F65). Empty means the API is mounted but lease issuance fails
	// closed with 503.
	DynamicProviders []dynsecret.Provider
	// DynamicProvidersForTenant is the production resolver. It prevents one
	// tenant's configured upstream authority from appearing in another tenant's
	// lease engine. DynamicProviders remains only as an embed/test compatibility
	// seam and is used when this resolver is nil.
	DynamicProvidersForTenant func(tenantID string) []dynsecret.Provider
	// DynamicLifecycleForTenant supplies the restart-safe production lifecycle.
	// When nil, the API constructs the reference in-memory Engine for embedders and
	// tests from DynamicProviders.
	DynamicLifecycleForTenant func(tenantID string) (dynsecret.Lifecycle, error)
	// DynamicLifecycleTenantIDs enumerates configured tenants so the restart-time
	// expiry worker recovers durable leases before a tenant sends a new request.
	DynamicLifecycleTenantIDs func() []string
	// DynamicRevokeQueue returns the tenant-scoped durable revocation queue. The
	// server wires this to the PostgreSQL outbox; embedders may supply their own.
	DynamicRevokeQueue func(tenantID string) dynsecret.RevokeQueue
	// DynamicLeaseWorkerInterval controls the served leaseworker cadence. Zero uses
	// the leaseworker default.
	DynamicLeaseWorkerInterval time.Duration
	// SecretRotators are the configured static-credential rotation engines exposed by
	// POST /api/v1/secrets/rotations (F37). Empty means the route is mounted but fails
	// closed with 503.
	SecretRotators map[string]rotation.Rotator
	// SecretSyncTargets are the configured outbound secret-sync targets exposed by
	// POST /api/v1/secrets/syncs (F68). Empty means the route is mounted but fails
	// closed with 503.
	SecretSyncTargets map[string]*secretsync.Target
	// SecretSyncTargetsForTenant is the production resolver. Target names and
	// credentials are tenant-bound; the legacy static map is used only when this
	// resolver is nil.
	SecretSyncTargetsForTenant func(tenantID string) map[string]*secretsync.Target
	// QueueSecretSync is the production event+sealed-outbox command. It returns
	// after durable enqueue; the process-wide outbox worker performs the external
	// write. Nil uses the legacy Engine path for embedded tests.
	QueueSecretSync func(ctx context.Context, tenantID, secretName string, secretVersion int, target, remoteKey, idempotencyKey, requestBinding string, value []byte) error
	// SecretSyncOutbox returns the tenant/target durable outbox used before any
	// external sync write is attempted (AN-6). The server wires this to the sealed
	// PostgreSQL outbox; embedders may supply their own.
	SecretSyncOutbox func(tenantID, target string) secretsync.Outbox
	// SecretScanner invokes the configured code/CI secret scanner. The served binary
	// wires this to a Gitleaks subprocess runner; nil leaves POST /secrets/scans
	// fail-closed while the rest of the secrets surface remains available.
	SecretScanner SecretScanner
}

// secretsService is the assembled served secrets surface. It owns the per-request
// construction of the tenant-scoped frameworks (AN-1) and the dynamic lease engines.
// One-time share links are durable rows in PostgreSQL, not process memory, so valid
// shares survive an API restart.
type secretsService struct {
	be SecretsBackend

	mu     sync.Mutex
	leases map[string]dynsecret.Lifecycle // tenant -> dynamic lease lifecycle
}

func (s *secretsService) dynamicProviders(tenantID string) []dynsecret.Provider {
	if s.be.DynamicProvidersForTenant != nil {
		return s.be.DynamicProvidersForTenant(tenantID)
	}
	return append([]dynsecret.Provider(nil), s.be.DynamicProviders...)
}

func (s *secretsService) syncTargets(tenantID string) map[string]*secretsync.Target {
	if s.be.SecretSyncTargetsForTenant != nil {
		return s.be.SecretSyncTargetsForTenant(tenantID)
	}
	out := make(map[string]*secretsync.Target, len(s.be.SecretSyncTargets))
	for id, target := range s.be.SecretSyncTargets {
		out[id] = target
	}
	return out
}

func (s *secretsService) withTenantCipher(ctx context.Context, tenantID string, fn func(tenantseal.Cipher) error) error {
	if cipher, ok := ctx.Value(tenantCipherCtxKey).(tenantseal.Cipher); ok {
		return fn(cipher)
	}
	if s.be.TenantCrypto != nil {
		return s.be.TenantCrypto.WithTenant(ctx, tenantID, fn)
	}
	if s.be.KEK == nil {
		return errors.New("api: tenant cryptographic access is not configured")
	}
	return fn(legacySecretsCipher{wrapper: s.be.KEK})
}

// guardTenantCrypto holds one shared tenant-domain fence across the complete
// authenticated secrets request, including its store work and idempotency-result
// commit. A concurrent seal therefore either waits for this request to finish or
// rejects the request before its handler can observe or mutate tenant state.
func (a *API) guardTenantCrypto(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.secrets == nil || a.secrets.be.TenantCrypto == nil {
			next(w, r)
			return
		}
		tenantID, ok := a.tenant(r)
		if !ok {
			a.writeProblem(w, problemUnauthorized())
			return
		}
		err := a.secrets.withTenantCipher(r.Context(), tenantID, func(cipher tenantseal.Cipher) error {
			ctx := context.WithValue(r.Context(), tenantCipherCtxKey, cipher)
			next(w, r.WithContext(ctx))
			return nil
		})
		if err != nil {
			a.writeError(w, err)
		}
	}
}

func (s *secretsService) seal(ctx context.Context, tenantID string, plaintext, aad []byte) ([]byte, error) {
	var sealed []byte
	err := s.withTenantCipher(ctx, tenantID, func(cipher tenantseal.Cipher) (err error) {
		sealed, err = cipher.Seal(plaintext, aad)
		return err
	})
	if err != nil {
		secret.Wipe(sealed)
		return nil, err
	}
	return sealed, err
}

func (s *secretsService) open(ctx context.Context, tenantID string, container, aad []byte) ([]byte, error) {
	var plaintext []byte
	err := s.withTenantCipher(ctx, tenantID, func(cipher tenantseal.Cipher) (err error) {
		plaintext, err = cipher.Open(container, aad)
		return err
	})
	if err != nil {
		secret.Wipe(plaintext)
		return nil, err
	}
	return plaintext, err
}

type legacySecretsCipher struct{ wrapper seal.KeyWrapper }

func (c legacySecretsCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	return seal.Seal(c.wrapper, plaintext, aad)
}

func (c legacySecretsCipher) Open(container, aad []byte) ([]byte, error) {
	return seal.Open(c.wrapper, container, aad)
}

// WithSecrets mounts the served secrets/identity surface (GAP-006). The KEK, store,
// and audit sink are required; the issuing CA + auth secret are optional and gate
// their sub-features. When unset, the /api/v1/secrets/* routes fail closed with a
// clear "not enabled" problem.
func WithSecrets(be SecretsBackend) Option {
	return func(c *config) {
		c.secrets = &secretsService{
			be: be, leases: map[string]dynsecret.Lifecycle{},
		}
	}
}

// SecretsServed reports whether the served secrets surface is wired (WithSecrets was
// given). It is the GAP-006 wiring assertion the acceptance test consults.
func (a *API) SecretsServed() bool { return a.secrets != nil }

// RunDynamicLeaseWorker runs the served dynamic-secret leaseworker until ctx is
// cancelled. server.Run starts this alongside the other bounded background workers;
// tests call it directly against the assembled server.
func (a *API) RunDynamicLeaseWorker(ctx context.Context) {
	interval := 30 * time.Second
	if a.secrets != nil && a.secrets.be.DynamicLeaseWorkerInterval > 0 {
		interval = a.secrets.be.DynamicLeaseWorkerInterval
	}
	apiTokenWorker := leaseworker.New(apiTokenLeaseEngine{orch: a.orch}, interval)
	if a.secrets != nil {
		a.secrets.ensureDynamicLifecycleTenants()
		a.secrets.tickDynamicLeases(ctx)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if a.secrets != nil {
				for _, engine := range a.secrets.dynamicLeaseEngines() {
					_, _ = leaseworker.New(engine, interval).Recover(context.Background())
				}
			}
			_, _ = apiTokenWorker.Recover(context.Background())
			return
		case <-t.C:
			if a.secrets != nil {
				a.secrets.tickDynamicLeases(ctx)
			}
			_, _, _ = apiTokenWorker.Tick(ctx)
		}
	}
}

// secretStoreScope is the seal AAD scope binding application secrets in the secret
// store, so a sealed blob cannot be lifted to another row and still open.
const secretStoreScope = "secret-store"

// sealAAD binds a sealed application-secret blob to (tenant, name) so it cannot be
// moved to another tenant/name and still decrypt (AN-8).
func sealAAD(tenantID, name string) []byte {
	return []byte(tenantID + "/" + secretStoreScope + "/" + name)
}

// ---- secret store: CRUD + rotation -----------------------------------------

type secretWriteRequest struct {
	Name  string          `json:"name"`
	Value secretJSONBytes `json:"value"`
}

type secretImportRequest struct {
	Prefix string                     `json:"prefix"`
	Values map[string]secretJSONBytes `json:"values"`
}

// secretMetaResponse is the metadata view of a secret. It NEVER carries the value —
// a create/rotate/list reply discloses only name + version + timestamps, so a secret
// value is returned exclusively by an explicit read (AN-8).
type secretMetaResponse struct {
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toSecretMeta(s store.Secret) secretMetaResponse {
	return secretMetaResponse{Name: s.Name, Version: s.Version, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}
}

// secretValueResponse is the read view: the value is returned only here, only to the
// authorized caller — the one place a stored secret leaves the boundary by design.
type secretValueResponse struct {
	Name    string          `json:"name"`
	Value   secretJSONBytes `json:"value"`
	Version int             `json:"version"`
}

func (r secretValueResponse) wipeSecrets() { r.Value.wipe() }

type secretRecoverRequest struct {
	At time.Time `json:"at"`
}

type secretRotationRequest struct {
	Provider   string `json:"provider"`
	Key        string `json:"key"`
	OldRef     string `json:"old_ref"`
	Target     string `json:"target,omitempty"`
	RemoteKey  string `json:"remote_key,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type secretRotationResponse struct {
	Key               string `json:"key"`
	OldRef            string `json:"old_ref"`
	NewRef            string `json:"new_ref"`
	Completed         bool   `json:"completed"`
	RolledBack        bool   `json:"rolled_back"`
	RollbackAttempted bool   `json:"rollback_attempted"`
	RollbackFailed    bool   `json:"rollback_failed"`
	RollbackError     string `json:"rollback_error,omitempty"`
	FailedPhase       string `json:"failed_phase,omitempty"`
	Error             string `json:"error,omitempty"`
}

type secretRotationScheduleRequest struct {
	Name            string     `json:"name"`
	Provider        string     `json:"provider"`
	Key             string     `json:"key"`
	OldRef          string     `json:"old_ref"`
	IntervalSeconds int        `json:"interval_seconds"`
	Enabled         *bool      `json:"enabled"`
	NextRunAt       *time.Time `json:"next_run_at,omitempty"`
}

type secretRotationScheduleResponse struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	Name            string     `json:"name"`
	Provider        string     `json:"provider"`
	Key             string     `json:"key"`
	OldRef          string     `json:"old_ref"`
	IntervalSeconds int        `json:"interval_seconds"`
	Enabled         bool       `json:"enabled"`
	NextRunAt       time.Time  `json:"next_run_at"`
	LastRunID       *string    `json:"last_run_id,omitempty"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	LastRunStatus   string     `json:"last_run_status"`
	LastNewRef      string     `json:"last_new_ref,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type secretRotationScheduleRunResponse struct {
	ScheduleID string                 `json:"schedule_id"`
	RunID      string                 `json:"run_id"`
	Status     string                 `json:"status"`
	Rotation   secretRotationResponse `json:"rotation"`
	Error      string                 `json:"error,omitempty"`
	RanAt      time.Time              `json:"ran_at"`
}

type secretRotationDueRunResponse struct {
	Ran  int                                 `json:"ran"`
	Runs []secretRotationScheduleRunResponse `json:"runs"`
}

func (r dynamicLeaseResponse) wipeSecrets() { r.Credential.wipe() }

// createSecret stores a new application secret (version 1), sealed at rest. The reply
// is metadata only (no value, AN-8). Idempotent (AN-5).
//
//trstctl:mutation
func (a *API) createSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretWriteRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.Name == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name is required")
		}
		if len(req.Value) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "value is required")
		}
		sealed, err := a.secrets.seal(ctx, tenantID, []byte(req.Value), sealAAD(tenantID, req.Name))
		req.Value.wipe() // wipe the transient plaintext; the store only sees ciphertext (AN-8)
		if err != nil {
			return 0, nil, err
		}
		rec, err := a.secrets.be.Store.PutSecret(ctx, tenantID, req.Name, sealed)
		if err != nil {
			if errors.Is(err, store.ErrSecretExists) {
				return 0, nil, errStatus(http.StatusConflict, "a secret with this name already exists; rotate it instead")
			}
			return 0, nil, err
		}
		a.auditSecretVersion(ctx, tenantID, rec, nil)
		a.auditSecret(ctx, "secret.created", tenantID, rec.Name, rec.Version)
		return http.StatusCreated, toSecretMeta(rec), nil
	})
}

// getSecret reads a stored secret's value through a secretsdk.Client (F64), so the
// served read is the SDK's fail-safe fetch path. The value is returned only here.
func (a *API) getSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	name := r.PathValue("name")
	if r.URL.Query().Get("resolve") == "true" {
		value, version, err := a.resolveSecretValue(r.Context(), tenantID, name, nil)
		if err != nil {
			a.writeSecretReferenceError(w, err)
			return
		}
		resp := secretValueResponse{Name: name, Value: secretJSONBytes(value), Version: version}
		a.writeJSON(w, http.StatusOK, resp)
		secret.Wipe(value)
		return
	}
	// Read through the secretsdk client (F64): the Fetcher unseals the stored blob for
	// THIS tenant; the SDK caches/auto-refreshes and fails safe. Closed after the read
	// so no secret lingers (AN-8).
	client := secretsdk.New(a.secrets.secretFetcher(tenantID), secretsdk.WithTenant(tenantID))
	defer client.Close()
	value, err := client.Get(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			a.writeProblem(w, problem.New(http.StatusNotFound, "no such secret"))
			return
		}
		a.writeError(w, err)
		return
	}
	version := 0
	if rec, gerr := a.secrets.be.Store.GetSecret(r.Context(), tenantID, name); gerr == nil {
		version = rec.Version
	}
	resp := secretValueResponse{Name: name, Value: secretJSONBytes(value), Version: version}
	a.writeJSON(w, http.StatusOK, resp)
	secret.Wipe(value)
}

// getSecretVersion reads one historical sealed version through the same explicit
// value-returning path as getSecret. It never lists values and never crosses tenant
// boundaries; the version row is tenant-RLS-scoped in PostgreSQL.
func (a *API) getSecretVersion(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	name := r.PathValue("name")
	version, err := strconv.Atoi(r.URL.Query().Get("version"))
	if err != nil || version <= 0 {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "version query parameter must be a positive integer"))
		return
	}
	rec, err := a.secrets.be.Store.GetSecretVersion(r.Context(), tenantID, name, version)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			a.writeProblem(w, problem.New(http.StatusNotFound, "no such secret version"))
			return
		}
		a.writeError(w, err)
		return
	}
	value, err := a.secrets.open(r.Context(), tenantID, rec.Sealed, sealAAD(tenantID, name))
	if err != nil {
		a.writeError(w, err)
		return
	}
	resp := secretValueResponse{Name: name, Value: secretJSONBytes(value), Version: rec.Version}
	a.writeJSON(w, http.StatusOK, resp)
	secret.Wipe(value)
}

// rotateSecret replaces a stored secret's value and bumps its version. The reply is
// metadata only (no value, AN-8). Idempotent (AN-5).
//
//trstctl:mutation
func (a *API) rotateSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	name := r.PathValue("name")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretWriteRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.Value) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "value is required")
		}
		if err := a.requireSecretApproval(ctx, tenantID, name, "rotate"); err != nil {
			req.Value.wipe()
			return 0, nil, err
		}
		sealed, err := a.secrets.seal(ctx, tenantID, []byte(req.Value), sealAAD(tenantID, name))
		req.Value.wipe()
		if err != nil {
			return 0, nil, err
		}
		rec, err := a.secrets.be.Store.RotateSecret(ctx, tenantID, name, sealed)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such secret")
			}
			return 0, nil, err
		}
		a.auditSecretVersion(ctx, tenantID, rec, nil)
		a.auditSecret(ctx, "secret.rotated", tenantID, rec.Name, rec.Version)
		return http.StatusOK, toSecretMeta(rec), nil
	})
}

// recoverSecretAt republishes the version that was current at req.At as a new
// current version. The response is metadata only; callers use getSecret to read the
// recovered value deliberately.
//
//trstctl:mutation
func (a *API) recoverSecretAt(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	name := r.PathValue("name")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretRecoverRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.At.IsZero() {
			return 0, nil, errStatus(http.StatusBadRequest, "at is required")
		}
		if err := a.requireSecretApproval(ctx, tenantID, name, "recover"); err != nil {
			return 0, nil, err
		}
		rec, src, err := a.secrets.be.Store.RecoverSecretAt(ctx, tenantID, name, req.At)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such secret version")
			}
			return 0, nil, err
		}
		a.auditSecretVersion(ctx, tenantID, rec, &src.Version)
		a.auditSecret(ctx, "secret.recovered", tenantID, rec.Name, rec.Version)
		return http.StatusOK, toSecretMeta(rec), nil
	})
}

// rotateStaticSecret drives a rollback-safe static credential rotation through the
// configured provider. The generated backend credential is published by the provider's
// cutover path and never returned by this API.
//
//trstctl:mutation
func (a *API) rotateStaticSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretRotationRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Provider = strings.TrimSpace(req.Provider)
		req.Key = strings.TrimSpace(req.Key)
		req.OldRef = strings.TrimSpace(req.OldRef)
		if req.Provider == "" || req.Key == "" || req.OldRef == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "provider, key, and old_ref are required")
		}
		rep, err := a.executeSecretRotation(ctx, tenantID, req)
		resp := toSecretRotationResponse(rep)
		if err != nil {
			resp.Error = err.Error()
			if rep.RollbackAttempted {
				return http.StatusConflict, resp, nil
			}
			return 0, nil, err
		}
		a.auditSecret(ctx, "secret.rotation.completed", tenantID, req.Key, 0)
		return http.StatusOK, resp, nil
	})
}

// createSecretRotationSchedule records a tenant cadence for zero-downtime
// dual-phase static credential rotation. It validates that the provider is
// configured now, so a schedule cannot claim automation that the served binary
// cannot execute.
//
//trstctl:mutation
func (a *API) createSecretRotationSchedule(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretRotationScheduleRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		name := strings.TrimSpace(req.Name)
		provider := strings.TrimSpace(req.Provider)
		key := strings.TrimSpace(req.Key)
		oldRef := strings.TrimSpace(req.OldRef)
		if name == "" || provider == "" || key == "" || oldRef == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name, provider, key, and old_ref are required")
		}
		if req.IntervalSeconds <= 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "interval_seconds must be greater than zero")
		}
		if _, err := a.secretRotatorFor(ctx, tenantID, secretRotationRequest{Provider: provider, Key: key, OldRef: oldRef}); err != nil {
			return 0, nil, err
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		nextRunAt := time.Time{}
		if req.NextRunAt != nil {
			nextRunAt = req.NextRunAt.UTC()
		}
		sched, err := a.orch.UpsertSecretRotationSchedule(ctx, tenantID, store.SecretRotationSchedule{
			Name: name, Provider: provider, Key: key, OldRef: oldRef,
			IntervalSeconds: req.IntervalSeconds, Enabled: enabled, NextRunAt: nextRunAt,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toSecretRotationScheduleResponse(sched), nil
	})
}

func (a *API) listSecretRotationSchedules(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListSecretRotationSchedulesPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]secretRotationScheduleResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toSecretRotationScheduleResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

// runDueSecretRotationSchedules is the served scheduler tick for CAP-SECR-06: it
// finds enabled schedules due for this tenant and drives each through the same
// stage -> cutover -> verify -> retire engine as manual rotation.
//
//trstctl:mutation
func (a *API) runDueSecretRotationSchedules(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		rows, err := a.store.ListDueSecretRotationSchedules(ctx, tenantID, time.Now().UTC(), 50)
		if err != nil {
			return 0, nil, err
		}
		resp := secretRotationDueRunResponse{Runs: make([]secretRotationScheduleRunResponse, 0, len(rows))}
		for _, sched := range rows {
			run, err := a.runSecretRotationSchedule(ctx, tenantID, sched)
			if err != nil {
				return 0, nil, err
			}
			resp.Runs = append(resp.Runs, run)
		}
		resp.Ran = len(resp.Runs)
		return http.StatusOK, resp, nil
	})
}

func (a *API) runSecretRotationSchedule(ctx context.Context, tenantID string, sched store.SecretRotationSchedule) (secretRotationScheduleRunResponse, error) {
	status := "failed"
	errText := ""
	rep, err := a.executeSecretRotation(ctx, tenantID, secretRotationRequest{
		Provider: sched.Provider, Key: sched.Key, OldRef: sched.OldRef,
	})
	report := rep
	if err != nil {
		errText = err.Error()
		if rep.RollbackFailed {
			status = "rollback_failed"
		} else if rep.RollbackAttempted && rep.RolledBack {
			status = "rolled_back"
		}
	} else if rep.Completed {
		status = "completed"
	}
	rotationResp := toSecretRotationResponse(report)
	rotationResp.Error = errText
	run, err := a.orch.RecordSecretRotationScheduleRun(ctx, tenantID, store.SecretRotationScheduleRun{
		ScheduleID: sched.ID, Status: status, NewRef: report.NewRef, Error: errText,
	})
	if err != nil {
		return secretRotationScheduleRunResponse{}, err
	}
	if status == "completed" {
		a.auditSecret(ctx, "secret.rotation_schedule.completed", tenantID, sched.Key, 0)
	}
	return secretRotationScheduleRunResponse{
		ScheduleID: sched.ID, RunID: run.RunID, Status: status,
		Rotation: rotationResp, Error: errText, RanAt: run.RanAt,
	}, nil
}

const (
	secretConnectorRotationPrefix    = "connector:"
	secretDynamicLeaseRotationPrefix = "dynamic-lease:"
	defaultDynamicLeaseRotationTTL   = time.Hour
)

func (a *API) executeSecretRotation(ctx context.Context, tenantID string, req secretRotationRequest) (rotation.Report, error) {
	rotator, err := a.secretRotatorFor(ctx, tenantID, req)
	if err != nil {
		return rotation.Report{Key: strings.TrimSpace(req.Key), OldRef: strings.TrimSpace(req.OldRef)}, err
	}
	engine := rotation.New(tenantID, rotator, a.secrets.be.Audit)
	return engine.Rotate(ctx, strings.TrimSpace(req.Key), strings.TrimSpace(req.OldRef))
}

func (a *API) secretRotatorFor(ctx context.Context, tenantID string, req secretRotationRequest) (rotation.Rotator, error) {
	provider := strings.TrimSpace(req.Provider)
	key := strings.TrimSpace(req.Key)
	oldRef := strings.TrimSpace(req.OldRef)
	if provider == "" || key == "" || oldRef == "" {
		return nil, errStatus(http.StatusBadRequest, "provider, key, and old_ref are required")
	}
	if rotator := a.secrets.be.SecretRotators[provider]; rotator != nil {
		return rotator, nil
	}
	if strings.HasPrefix(provider, secretConnectorRotationPrefix) || provider == "connector" {
		targetID := strings.TrimSpace(req.Target)
		if strings.HasPrefix(provider, secretConnectorRotationPrefix) {
			targetID = strings.TrimSpace(strings.TrimPrefix(provider, secretConnectorRotationPrefix))
		}
		return a.connectorSecretRotator(tenantID, targetID, req.RemoteKey)
	}
	if strings.HasPrefix(provider, secretDynamicLeaseRotationPrefix) {
		dynamicProvider := strings.TrimSpace(strings.TrimPrefix(provider, secretDynamicLeaseRotationPrefix))
		return a.dynamicLeaseSecretRotator(ctx, tenantID, dynamicProvider, req)
	}
	return nil, errStatus(http.StatusServiceUnavailable, "secret rotation provider is not configured")
}

func (a *API) connectorSecretRotator(tenantID, targetID, remoteKey string) (rotation.Rotator, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return nil, errStatus(http.StatusBadRequest, "connector rotation target is required")
	}
	target := a.secrets.syncTargets(tenantID)[targetID]
	if target == nil {
		return nil, errStatus(http.StatusServiceUnavailable, "secret sync target is not configured")
	}
	if a.secrets.be.SecretSyncOutbox == nil {
		return nil, errStatus(http.StatusServiceUnavailable, "secret sync outbox is not configured")
	}
	return &connectorSecretRotator{
		api: a, tenantID: tenantID, targetID: targetID, target: target,
		remoteKey: strings.TrimSpace(remoteKey), staged: map[string]*connectorRotationState{},
	}, nil
}

func (a *API) dynamicLeaseSecretRotator(ctx context.Context, tenantID, provider string, req secretRotationRequest) (rotation.Rotator, error) {
	if provider == "" {
		return nil, errStatus(http.StatusBadRequest, "dynamic-lease rotation provider is required")
	}
	targetID := strings.TrimSpace(req.Target)
	if targetID == "" {
		return nil, errStatus(http.StatusBadRequest, "target is required for dynamic-lease rotation")
	}
	target := a.secrets.syncTargets(tenantID)[targetID]
	if target == nil {
		return nil, errStatus(http.StatusServiceUnavailable, "secret sync target is not configured")
	}
	if a.secrets.be.SecretSyncOutbox == nil {
		return nil, errStatus(http.StatusServiceUnavailable, "secret sync outbox is not configured")
	}
	engine, err := a.secrets.dynamicLeaseEngine(tenantID)
	if err != nil {
		return nil, err
	}
	ttl := defaultDynamicLeaseRotationTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	return &dynamicLeaseRotationRotator{
		api: a, tenantID: tenantID, provider: provider, targetID: targetID,
		target: target, remoteKey: strings.TrimSpace(req.RemoteKey), ttl: ttl,
		engine: engine, issueIdempotencyKey: "rotation:" + provider + ":" + strings.TrimSpace(req.Key) + ":" + strings.TrimSpace(req.OldRef),
		staged: map[string]*dynamicLeaseRotationState{},
	}, nil
}

type connectorSecretRotator struct {
	api       *API
	tenantID  string
	targetID  string
	target    *secretsync.Target
	remoteKey string

	mu     sync.Mutex
	staged map[string]*connectorRotationState
}

type connectorRotationState struct {
	newRef     string
	newValue   []byte
	oldVersion int
}

func (r *connectorSecretRotator) Stage(ctx context.Context, key string) (string, error) {
	rec, err := r.api.secrets.be.Store.GetSecret(ctx, r.tenantID, key)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			return "", errStatus(http.StatusNotFound, "no such secret")
		}
		return "", err
	}
	raw, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	value := []byte("rotated-" + hex.EncodeToString(raw))
	secret.Wipe(raw)
	state := &connectorRotationState{
		newRef:     fmt.Sprintf("version:%d", rec.Version+1),
		newValue:   value,
		oldVersion: rec.Version,
	}
	r.mu.Lock()
	if old := r.staged[key]; old != nil {
		old.destroy()
	}
	r.staged[key] = state
	r.mu.Unlock()
	return state.newRef, nil
}

func (r *connectorSecretRotator) Cutover(ctx context.Context, key, newRef string) error {
	state := r.stagedFor(key, newRef)
	if state == nil {
		return rotation.ErrCredentialNotFound
	}
	sealed, err := r.api.secrets.seal(ctx, r.tenantID, state.newValue, sealAAD(r.tenantID, key))
	if err != nil {
		return err
	}
	rec, err := r.api.secrets.be.Store.RotateSecret(ctx, r.tenantID, key, sealed)
	if err != nil {
		return err
	}
	if got := fmt.Sprintf("version:%d", rec.Version); got != newRef {
		return fmt.Errorf("rotation: connector version advanced to %s, want %s", got, newRef)
	}
	r.api.auditSecretVersion(ctx, r.tenantID, rec, nil)
	r.api.auditSecret(ctx, "secret.rotated", r.tenantID, rec.Name, rec.Version)
	remoteKey := r.remoteKeyFor(key)
	delivered, err := r.api.syncRotationCredential(ctx, r.tenantID, r.targetID, remoteKey, r.target, state.newValue)
	if err != nil {
		return err
	}
	if delivered == 0 {
		return errors.New("rotation: connector delivery did not complete")
	}
	_ = auditsink.Emit(ctx, r.api.secrets.be.Audit, nil, "secret.rotation.connector_cutover", r.tenantID,
		[]byte(fmt.Sprintf(`{"key":%q,"target":%q,"new_ref":%q}`, key, r.targetID, newRef)))
	return nil
}

func (r *connectorSecretRotator) Verify(context.Context, string) error { return nil }

func (r *connectorSecretRotator) Retire(_ context.Context, key, _ string) error {
	r.cleanup(key)
	return nil
}

func (r *connectorSecretRotator) Rollback(ctx context.Context, key, oldRef string) error {
	version, err := parseSecretVersionRef(oldRef)
	if err != nil {
		r.cleanup(key)
		return err
	}
	rec, err := r.api.secrets.be.Store.GetSecretVersion(ctx, r.tenantID, key, version)
	if err != nil {
		r.cleanup(key)
		return err
	}
	value, err := r.api.secrets.open(ctx, r.tenantID, rec.Sealed, sealAAD(r.tenantID, key))
	if err != nil {
		r.cleanup(key)
		return err
	}
	defer secret.Wipe(value)
	sealed, err := r.api.secrets.seal(ctx, r.tenantID, value, sealAAD(r.tenantID, key))
	if err != nil {
		r.cleanup(key)
		return err
	}
	restored, err := r.api.secrets.be.Store.RotateSecret(ctx, r.tenantID, key, sealed)
	if err != nil {
		r.cleanup(key)
		return err
	}
	r.api.auditSecretVersion(ctx, r.tenantID, restored, &version)
	r.api.auditSecret(ctx, "secret.recovered", r.tenantID, restored.Name, restored.Version)
	remoteKey := r.remoteKeyFor(key)
	delivered, err := r.api.syncRotationCredential(ctx, r.tenantID, r.targetID, remoteKey, r.target, value)
	r.cleanup(key)
	if err != nil {
		return err
	}
	if delivered == 0 {
		return errors.New("rotation: connector rollback delivery did not complete")
	}
	_ = auditsink.Emit(ctx, r.api.secrets.be.Audit, nil, "secret.rotation.connector_rolled_back", r.tenantID,
		[]byte(fmt.Sprintf(`{"key":%q,"target":%q,"old_ref":%q}`, key, r.targetID, oldRef)))
	return nil
}

func (r *connectorSecretRotator) stagedFor(key, ref string) *connectorRotationState {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.staged[key]
	if state == nil {
		return nil
	}
	if ref != "" && state.newRef != ref {
		return nil
	}
	return state
}

func (r *connectorSecretRotator) cleanup(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if state := r.staged[key]; state != nil {
		state.destroy()
		delete(r.staged, key)
	}
}

func (r *connectorSecretRotator) remoteKeyFor(key string) string {
	if r.remoteKey != "" {
		return r.remoteKey
	}
	return key
}

func (s *connectorRotationState) destroy() {
	secret.Wipe(s.newValue)
	s.newValue = nil
}

type dynamicLeaseRotationRotator struct {
	api                 *API
	tenantID            string
	provider            string
	targetID            string
	target              *secretsync.Target
	remoteKey           string
	ttl                 time.Duration
	engine              dynsecret.Lifecycle
	issueIdempotencyKey string

	mu     sync.Mutex
	staged map[string]*dynamicLeaseRotationState
}

type dynamicLeaseRotationState struct {
	newLeaseID string
	credential []byte
}

func (r *dynamicLeaseRotationRotator) Stage(ctx context.Context, key string) (string, error) {
	lease, credential, err := r.engine.Issue(ctx, r.provider, key, r.ttl, r.issueIdempotencyKey)
	if err != nil {
		return "", dynamicLeaseError(err)
	}
	state := &dynamicLeaseRotationState{newLeaseID: lease.ID, credential: credential}
	r.mu.Lock()
	if old := r.staged[key]; old != nil {
		old.destroy()
	}
	r.staged[key] = state
	r.mu.Unlock()
	return lease.ID, nil
}

func (r *dynamicLeaseRotationRotator) Cutover(ctx context.Context, key, newRef string) error {
	state := r.stagedFor(key, newRef)
	if state == nil {
		return rotation.ErrCredentialNotFound
	}
	remoteKey := r.remoteKeyFor(key)
	delivered, err := r.api.syncRotationCredential(ctx, r.tenantID, r.targetID, remoteKey, r.target, state.credential)
	if err != nil {
		return err
	}
	if delivered == 0 {
		return errors.New("rotation: dynamic lease connector delivery did not complete")
	}
	_ = auditsink.Emit(ctx, r.api.secrets.be.Audit, nil, "secret.rotation.dynamic_cutover", r.tenantID,
		[]byte(fmt.Sprintf(`{"role":%q,"provider":%q,"target":%q,"new_ref":%q}`, key, r.provider, r.targetID, newRef)))
	return nil
}

func (r *dynamicLeaseRotationRotator) Verify(context.Context, string) error { return nil }

func (r *dynamicLeaseRotationRotator) Retire(ctx context.Context, key, oldRef string) error {
	if err := r.engine.Revoke(ctx, oldRef); err != nil {
		return dynamicLeaseError(err)
	}
	if _, err := r.engine.RunRevocations(ctx); err != nil {
		return err
	}
	r.cleanup(key)
	return nil
}

func (r *dynamicLeaseRotationRotator) Rollback(ctx context.Context, key, _ string) error {
	state := r.stagedFor(key, "")
	if state == nil {
		return rotation.ErrCredentialNotFound
	}
	err := r.engine.Revoke(ctx, state.newLeaseID)
	if err == nil {
		_, err = r.engine.RunRevocations(ctx)
	}
	r.cleanup(key)
	return dynamicLeaseError(err)
}

func (r *dynamicLeaseRotationRotator) stagedFor(key, ref string) *dynamicLeaseRotationState {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.staged[key]
	if state == nil {
		return nil
	}
	if ref != "" && state.newLeaseID != ref {
		return nil
	}
	return state
}

func (r *dynamicLeaseRotationRotator) cleanup(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if state := r.staged[key]; state != nil {
		state.destroy()
		delete(r.staged, key)
	}
}

func (r *dynamicLeaseRotationRotator) remoteKeyFor(key string) string {
	if r.remoteKey != "" {
		return r.remoteKey
	}
	return key
}

func (s *dynamicLeaseRotationState) destroy() {
	secret.Wipe(s.credential)
	s.credential = nil
}

func (a *API) syncRotationCredential(ctx context.Context, tenantID, targetID, remoteKey string, target *secretsync.Target, value []byte) (int, error) {
	valueCopy := append([]byte(nil), value...)
	defer secret.Wipe(valueCopy)
	outbox := &rotationTrackingOutbox{Outbox: a.secrets.be.SecretSyncOutbox(tenantID, targetID)}
	engine := secretsync.New(tenantID, target, outbox, a.secrets.be.Audit)
	if err := engine.Sync(ctx, remoteKey, valueCopy); err != nil {
		return 0, err
	}
	delivered, err := engine.RunDeliveries(ctx)
	if delivered == 0 {
		for _, id := range outbox.ids() {
			_ = outbox.Done(ctx, id)
		}
	}
	return delivered, err
}

func parseSecretVersionRef(ref string) (int, error) {
	const prefix = "version:"
	if !strings.HasPrefix(ref, prefix) {
		return 0, errStatus(http.StatusBadRequest, "connector rotation old_ref must be version:<n>")
	}
	version, err := strconv.Atoi(strings.TrimPrefix(ref, prefix))
	if err != nil || version <= 0 {
		return 0, errStatus(http.StatusBadRequest, "connector rotation old_ref must be version:<n>")
	}
	return version, nil
}

type rotationTrackingOutbox struct {
	secretsync.Outbox
	mu       sync.Mutex
	enqueued []string
}

func (o *rotationTrackingOutbox) Enqueue(ctx context.Context, item secretsync.SyncItem) error {
	o.mu.Lock()
	o.enqueued = append(o.enqueued, item.ID)
	o.mu.Unlock()
	return o.Outbox.Enqueue(ctx, item)
}

func (o *rotationTrackingOutbox) ids() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.enqueued...)
}

type secretVisibilitySourceCounts struct {
	Repository int
	ThirdParty int
	Cloud      int
}

// importSecrets atomically imports a flat tree of application secrets under an
// optional prefix. Each value is sealed independently, and the response returns only
// metadata. Idempotent (AN-5).
//
//trstctl:mutation
func (a *API) importSecrets(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretImportRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if len(req.Values) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "values must contain at least one secret")
		}
		keys := make([]string, 0, len(req.Values))
		for key := range req.Values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		seen := map[string]bool{}
		entries := make([]store.SecretImportEntry, 0, len(keys))
		for _, key := range keys {
			name, err := normalizeImportedSecretName(req.Prefix, key)
			if err != nil {
				return 0, nil, errStatus(http.StatusBadRequest, err.Error())
			}
			if seen[name] {
				return 0, nil, errStatus(http.StatusBadRequest, "import contains duplicate secret path "+name)
			}
			seen[name] = true
			value := req.Values[key]
			if len(value) == 0 {
				return 0, nil, errStatus(http.StatusBadRequest, "value is required for "+name)
			}
			sealed, err := a.secrets.seal(ctx, tenantID, []byte(value), sealAAD(tenantID, name))
			value.wipe()
			if err != nil {
				return 0, nil, err
			}
			entries = append(entries, store.SecretImportEntry{Name: name, Sealed: sealed})
		}
		recs, err := a.secrets.be.Store.PutSecrets(ctx, tenantID, entries)
		if err != nil {
			if errors.Is(err, store.ErrSecretExists) {
				return 0, nil, errStatus(http.StatusConflict, "a secret in this import already exists; rotate it instead")
			}
			return 0, nil, err
		}
		items := make([]secretMetaResponse, 0, len(recs))
		for _, rec := range recs {
			a.auditSecretVersion(ctx, tenantID, rec, nil)
			a.auditSecret(ctx, "secret.imported", tenantID, rec.Name, rec.Version)
			items = append(items, toSecretMeta(rec))
		}
		return http.StatusCreated, listResponse{Items: items}, nil
	})
}

// deleteSecret removes a stored secret. Idempotent (AN-5); a missing secret is 404.
//
//trstctl:mutation
func (a *API) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	name := r.PathValue("name")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if err := a.requireSecretApproval(ctx, tenantID, name, "delete"); err != nil {
			return 0, nil, err
		}
		if err := a.secrets.be.Store.PurgeSecret(ctx, tenantID, name); err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such secret")
			}
			return 0, nil, err
		}
		a.auditSecret(ctx, "secret.deleted", tenantID, name, 0)
		return http.StatusNoContent, nil, nil
	})
}

// listSecrets returns the tenant's secret NAMES + versions (no values, AN-8).
func (a *API) listSecrets(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	recs, err := a.secrets.be.Store.ListSecretNames(r.Context(), tenantID, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]secretMetaResponse, 0, len(recs))
	for _, rec := range recs {
		items = append(items, toSecretMeta(rec))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func normalizeImportedSecretName(prefix, key string) (string, error) {
	prefix = strings.Trim(prefix, "/")
	key = strings.Trim(key, "/")
	if key == "" {
		return "", errors.New("import secret path is required")
	}
	if strings.Contains(key, "//") || strings.Contains(prefix, "//") {
		return "", errors.New("import secret paths must not contain empty segments")
	}
	if prefix == "" {
		return key, nil
	}
	return prefix + "/" + key, nil
}

func toSecretRotationResponse(rep rotation.Report) secretRotationResponse {
	return secretRotationResponse{
		Key: rep.Key, OldRef: rep.OldRef, NewRef: rep.NewRef, Completed: rep.Completed,
		RolledBack: rep.RolledBack, RollbackAttempted: rep.RollbackAttempted,
		RollbackFailed: rep.RollbackFailed, RollbackError: rep.RollbackError,
		FailedPhase: rep.FailedPhase,
	}
}

func toSecretRotationScheduleResponse(s store.SecretRotationSchedule) secretRotationScheduleResponse {
	return secretRotationScheduleResponse{
		ID: s.ID, TenantID: s.TenantID, Name: s.Name, Provider: s.Provider, Key: s.Key,
		OldRef: s.OldRef, IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled,
		NextRunAt: s.NextRunAt, LastRunID: s.LastRunID, LastRunAt: s.LastRunAt,
		LastRunStatus: s.LastRunStatus, LastNewRef: s.LastNewRef, LastError: s.LastError,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

type secretReferenceCycleError struct {
	Cycle []string
}

func (e secretReferenceCycleError) Error() string { return "secret reference cycle detected" }

type secretReferenceDepthError struct{}

func (secretReferenceDepthError) Error() string { return "secret reference depth exceeded" }

const (
	secretReferenceStart = "${secret."
	secretReferenceEnd   = byte('}')
	secretReferenceLimit = 32
)

func (a *API) resolveSecretValue(ctx context.Context, tenantID, name string, stack []string) ([]byte, int, error) {
	if len(stack) >= secretReferenceLimit {
		return nil, 0, secretReferenceDepthError{}
	}
	for _, current := range stack {
		if current == name {
			cycle := append(append([]string(nil), stack...), name)
			return nil, 0, secretReferenceCycleError{Cycle: cycle}
		}
	}
	rec, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name)
	if err != nil {
		return nil, 0, err
	}
	plain, err := a.secrets.open(ctx, tenantID, rec.Sealed, sealAAD(tenantID, name))
	if err != nil {
		return nil, 0, err
	}
	defer secret.Wipe(plain)
	resolved, err := a.expandSecretReferences(ctx, tenantID, plain, append(stack, name))
	if err != nil {
		return nil, 0, err
	}
	return resolved, rec.Version, nil
}

func (a *API) expandSecretReferences(ctx context.Context, tenantID string, value []byte, stack []string) ([]byte, error) {
	out := make([]byte, 0, len(value))
	rest := value
	for {
		idx := bytes.Index(rest, []byte(secretReferenceStart))
		if idx < 0 {
			out = append(out, rest...)
			return out, nil
		}
		out = append(out, rest[:idx]...)
		refBody := rest[idx+len(secretReferenceStart):]
		end := bytes.IndexByte(refBody, secretReferenceEnd)
		if end < 0 {
			out = append(out, rest[idx:]...)
			return out, nil
		}
		refName := string(refBody[:end])
		if refName == "" {
			secret.Wipe(out)
			return nil, errStatus(http.StatusBadRequest, "secret reference path is required")
		}
		refValue, _, err := a.resolveSecretValue(ctx, tenantID, refName, stack)
		if err != nil {
			secret.Wipe(out)
			return nil, err
		}
		out = append(out, refValue...)
		secret.Wipe(refValue)
		rest = refBody[end+1:]
	}
}

func (a *API) writeSecretReferenceError(w http.ResponseWriter, err error) {
	var cycle secretReferenceCycleError
	var depth secretReferenceDepthError
	switch {
	case errors.As(err, &cycle):
		a.writeProblem(w, problem.New(http.StatusConflict, "secret reference cycle detected").WithExtension("cycle", cycle.Cycle))
	case errors.As(err, &depth):
		a.writeProblem(w, problem.New(http.StatusConflict, "secret reference depth exceeded"))
	case errors.Is(err, store.ErrSecretNotFound):
		a.writeProblem(w, problem.New(http.StatusNotFound, "no such secret reference"))
	default:
		a.writeError(w, err)
	}
}

func (r shareCreateResponse) wipeSecrets() { r.Token.wipe() }

func (r shareRedeemResponse) wipeSecrets() { r.Value.wipe() }

func (r pkiSecretResponse) wipeSecrets() {
	r.Certificate.wipe()
	r.PrivateKey.wipe()
}

func (f fetcherFunc) Fetch(ctx context.Context, path string) ([]byte, time.Time, error) {
	return f(ctx, path)
}
