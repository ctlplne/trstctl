// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/leaseworker"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pkisecret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/rotationcommand"
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
	// CommandMAC computes server-keyed, domain-separated request/command evidence
	// without exposing its key. Exact application-secret mutations fail closed when
	// this is absent; a caller-controlled Idempotency-Key is never a MAC key.
	CommandMAC func(domain, material []byte) ([]byte, error)
	// Store is the relational backing for the secret store (sealed rows) and the
	// pkisecret revocation records, all under RLS (AN-1). Required.
	Store *store.Store
	// EventLog is the source of truth for served application-secret mutations.
	// The projector consumes exact approval authority beside the sealed store
	// update; nil keeps bare embedders on the legacy non-approval path only.
	EventLog *events.Log
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
	// SecretRotators retain configured static-credential engines for compatibility
	// and future durable workers. The HTTP route refuses them before invocation until
	// an independently recoverable phase receiver exists.
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
	// write. Nil makes the served mutation fail closed: every HTTP command must
	// create the event-backed job/order pair enforced by migration 0153.
	QueueSecretSync func(ctx context.Context, tenantID, secretName string, secretVersion int, target, remoteKey, idempotencyKey, requestBinding string, value []byte) error
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
		if a.tenantCrypto == nil {
			next(w, r)
			return
		}
		tenantID, ok := a.tenant(r)
		if !ok {
			a.writeProblem(w, problemUnauthorized())
			return
		}
		err := a.tenantCrypto.WithTenant(r.Context(), tenantID, func(cipher tenantseal.Cipher) error {
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
		if c.tenantCrypto == nil {
			c.tenantCrypto = be.TenantCrypto
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
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
}

type secretRotationResponse struct {
	Key               string `json:"key"`
	OldRef            string `json:"old_ref"`
	NewRef            string `json:"new_ref"`
	Completed         bool   `json:"completed"`
	Queued            bool   `json:"queued"`
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
	DueAt      time.Time              `json:"due_at"`
	Status     string                 `json:"status"`
	Rotation   secretRotationResponse `json:"rotation"`
	Error      string                 `json:"error,omitempty"`
	RanAt      time.Time              `json:"ran_at"`
	Reconciled bool                   `json:"reconciled"`
}

type secretRotationDueRunResponse struct {
	Ran              int                                      `json:"ran"`
	Scanned          int                                      `json:"scanned"`
	Runs             []secretRotationScheduleRunResponse      `json:"runs"`
	Deferred         []secretRotationScheduleDeferredResponse `json:"deferred"`
	RunLimitReached  bool                                     `json:"run_limit_reached"`
	ScanLimitReached bool                                     `json:"scan_limit_reached"`
	Complete         bool                                     `json:"complete"`
	Partial          bool                                     `json:"partial"`
	FailedScheduleID string                                   `json:"failed_schedule_id,omitempty"`
	SystemError      string                                   `json:"system_error,omitempty"`
}

type secretRotationScheduleDeferredResponse struct {
	ScheduleID string    `json:"schedule_id"`
	Reason     string    `json:"reason"`
	DueAt      time.Time `json:"due_at"`
	Error      string    `json:"error,omitempty"`
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
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req secretWriteRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer req.Value.wipe()
	if req.Name == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "name is required"))
		return
	}
	if len(req.Value) == 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "value is required"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	bindingTenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	keyDigest, requestBinding, err := a.applicationSecretRequestBinding(
		bindingTenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(), "create", "native", req.Name, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if tenantID != bindingTenantID {
			return 0, nil, errors.New("api: application-secret binding tenant changed")
		}
		const operation = "create"
		tenantEpoch, epochErr := a.applicationSecretTenantEpoch(ctx, tenantID)
		if epochErr != nil {
			return 0, nil, epochErr
		}
		eventID := applicationSecretMutationEventID(tenantID, tenantEpoch, req.Name, operation, keyDigest)
		if receipt, ok, receiptErr := a.applicationSecretMaterializedResult(
			ctx, tenantID, eventID, requestBinding, req.Name, "create"); receiptErr != nil {
			return 0, nil, applicationSecretMutationError(receiptErr)
		} else if ok {
			return http.StatusCreated, applicationSecretReceiptMeta(receipt), nil
		}
		fence, payload, prepared, fenceErr := a.applicationSecretMutationFence(
			ctx, tenantID, req.Name, operation, eventID, requestBinding)
		if fenceErr != nil {
			return 0, nil, applicationSecretMutationError(fenceErr)
		}
		if !prepared {
			if _, getErr := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Name); getErr == nil {
				return 0, nil, errStatus(http.StatusConflict, "a secret with this name already exists; rotate it instead")
			} else if !errors.Is(getErr, store.ErrSecretNotFound) {
				return 0, nil, getErr
			}
			commandKeyDigest, commandEvidence, commandErr := a.applicationSecretCommandEvidence(tenantID, idempotencyKey, canonicalApplicationSecretCommand{
				Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: tenantEpoch, Action: "create",
				Name: req.Name, Surface: "native", ResultVersion: 1, Value: []byte(req.Value),
			})
			if commandErr != nil {
				return 0, nil, commandErr
			}
			if commandKeyDigest != keyDigest {
				return 0, nil, errors.New("api: application-secret idempotency digest changed")
			}
			sealed, sealErr := a.secrets.seal(ctx, tenantID, []byte(req.Value), sealAAD(tenantID, req.Name))
			if sealErr != nil {
				return 0, nil, sealErr
			}
			payload = projections.ApplicationSecretMutation{
				TenantEpoch: tenantEpoch, Action: "create", Name: req.Name, ResultVersion: 1, Sealed: sealed,
				IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
				CommandEvidence: commandEvidence, Surface: "native",
			}
			fence, payload, fenceErr = a.claimApplicationSecretMutationFence(ctx, tenantID, req.Name,
				operation, eventID, projections.EventApplicationSecretCreated, requestBinding, payload)
			if fenceErr != nil {
				return 0, nil, applicationSecretMutationError(fenceErr)
			}
		}
		if fence.EventTime.IsZero() {
			fence, fenceErr = a.secrets.be.Store.FinalizeApplicationSecretMutationFence(
				ctx, tenantID, req.Name, eventID, nil, time.Now().UTC())
			if fenceErr != nil {
				return 0, nil, applicationSecretMutationError(fenceErr)
			}
		}
		if _, _, appendErr := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload); appendErr != nil {
			return 0, nil, applicationSecretMutationError(appendErr)
		}
		rec, getErr := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Name)
		if getErr != nil {
			return 0, nil, getErr
		}
		a.auditSecretVersion(ctx, tenantID, rec, nil)
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
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req secretWriteRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer req.Value.wipe()
	if len(req.Value) == 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "value is required"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	bindingTenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	keyDigest, requestBinding, err := a.applicationSecretRequestBinding(
		bindingTenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(), "rotate", "native", name, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if tenantID != bindingTenantID {
			return 0, nil, errors.New("api: application-secret binding tenant changed")
		}
		tenantEpoch, epochErr := a.applicationSecretTenantEpoch(ctx, tenantID)
		if epochErr != nil {
			return 0, nil, epochErr
		}
		eventID := applicationSecretMutationEventID(tenantID, tenantEpoch, name, "rotate", keyDigest)
		if receipt, ok, receiptErr := a.applicationSecretMaterializedResult(
			ctx, tenantID, eventID, requestBinding, name, "rotate"); receiptErr != nil {
			return 0, nil, applicationSecretMutationError(receiptErr)
		} else if ok {
			return http.StatusOK, applicationSecretReceiptMeta(receipt), nil
		}
		fence, payload, prepared, err := a.applicationSecretMutationFence(
			ctx, tenantID, name, "rotate", eventID, requestBinding)
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
		current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such secret")
			}
			return 0, nil, err
		}
		if !prepared {
			commandKeyDigest, commandEvidence, commandErr := a.applicationSecretCommandEvidence(tenantID, idempotencyKey, canonicalApplicationSecretCommand{
				Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: tenantEpoch, Action: "rotate",
				Name: name, Surface: "native", ExpectedVersion: current.Version,
				ResultVersion: current.Version + 1, Value: []byte(req.Value),
			})
			if commandErr != nil {
				return 0, nil, commandErr
			}
			if commandKeyDigest != keyDigest {
				return 0, nil, errors.New("api: application-secret idempotency digest changed")
			}
			sealed, sealErr := a.secrets.seal(ctx, tenantID, []byte(req.Value), sealAAD(tenantID, name))
			if sealErr != nil {
				return 0, nil, sealErr
			}
			payload = projections.ApplicationSecretMutation{
				TenantEpoch: tenantEpoch, Action: "rotate", Name: name, ExpectedVersion: current.Version,
				ResultVersion: current.Version + 1, Sealed: sealed,
				IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
				CommandEvidence: commandEvidence, Surface: "native",
			}
			fence, payload, err = a.claimApplicationSecretMutationFence(ctx, tenantID, name,
				"rotate", eventID, projections.EventApplicationSecretRotated, requestBinding, payload)
			if err != nil {
				return 0, nil, applicationSecretMutationError(err)
			}
		}
		fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, tenantID, fence, payload)
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
		event, canonical, err := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload)
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
		rec := applicationSecretResultMeta(current, event, canonical)
		a.auditSecretVersion(ctx, tenantID, rec, nil)
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
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req secretRecoverRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.At.IsZero() {
		a.writeError(w, errStatus(http.StatusBadRequest, "at is required"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	bindingTenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	keyDigest, requestBinding, err := a.applicationSecretRequestBinding(
		bindingTenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(), "recover", "native", name, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if tenantID != bindingTenantID {
			return 0, nil, errors.New("api: application-secret binding tenant changed")
		}
		tenantEpoch, epochErr := a.applicationSecretTenantEpoch(ctx, tenantID)
		if epochErr != nil {
			return 0, nil, epochErr
		}
		eventID := applicationSecretMutationEventID(tenantID, tenantEpoch, name, "recover", keyDigest)
		if receipt, ok, receiptErr := a.applicationSecretMaterializedResult(
			ctx, tenantID, eventID, requestBinding, name, "recover"); receiptErr != nil {
			return 0, nil, applicationSecretMutationError(receiptErr)
		} else if ok {
			return http.StatusOK, applicationSecretReceiptMeta(receipt), nil
		}
		fence, payload, prepared, err := a.applicationSecretMutationFence(
			ctx, tenantID, name, "recover", eventID, requestBinding)
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
		current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such secret")
			}
			return 0, nil, err
		}
		if !prepared {
			source, sourceErr := a.secrets.be.Store.GetSecretVersionAt(ctx, tenantID, name, req.At)
			if sourceErr != nil {
				if errors.Is(sourceErr, store.ErrSecretNotFound) {
					return 0, nil, errStatus(http.StatusNotFound, "no such secret version")
				}
				return 0, nil, sourceErr
			}
			commandKeyDigest, commandEvidence, commandErr := a.applicationSecretCommandEvidence(tenantID, idempotencyKey, canonicalApplicationSecretCommand{
				Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: tenantEpoch, Action: "recover",
				Name: name, Surface: "native", ExpectedVersion: current.Version,
				ResultVersion: current.Version + 1, RequestedAt: req.At.UTC(),
				SourceVersion: source.Version, SourceWrittenAt: source.WrittenAt.UTC(),
			})
			if commandErr != nil {
				return 0, nil, commandErr
			}
			if commandKeyDigest != keyDigest {
				return 0, nil, errors.New("api: application-secret idempotency digest changed")
			}
			payload = projections.ApplicationSecretMutation{
				TenantEpoch: tenantEpoch, Action: "recover", Name: name, ExpectedVersion: current.Version,
				ResultVersion: current.Version + 1, Sealed: source.Sealed,
				SourceVersion: source.Version, SourceWrittenAt: source.WrittenAt.UTC(),
				IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
				CommandEvidence: commandEvidence, Surface: "native",
			}
			fence, payload, err = a.claimApplicationSecretMutationFence(ctx, tenantID, name,
				"recover", eventID, projections.EventApplicationSecretRecovered, requestBinding, payload)
			if err != nil {
				return 0, nil, applicationSecretMutationError(err)
			}
		}
		fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, tenantID, fence, payload)
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
		event, canonical, err := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload)
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
		rec := applicationSecretResultMeta(current, event, canonical)
		srcVersion := canonical.SourceVersion
		a.auditSecretVersion(ctx, tenantID, rec, &srcVersion)
		return http.StatusOK, toSecretMeta(rec), nil
	})
}

// rotateStaticSecret queues connector rotation through one metadata-only route.
// Static and dynamic-lease providers fail closed before any provider call until
// one durable worker command owns every phase and its compensating actions.
//
//trstctl:mutation
func (a *API) rotateStaticSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	var req secretRotationRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.Provider = strings.TrimSpace(req.Provider)
	req.Key = strings.TrimSpace(req.Key)
	req.OldRef = strings.TrimSpace(req.OldRef)
	req.Target = strings.TrimSpace(req.Target)
	req.RemoteKey = strings.TrimSpace(req.RemoteKey)
	if req.Provider == "" || req.Key == "" || req.OldRef == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "provider, key, and old_ref are required"))
		return
	}
	if isConnectorSecretRotation(req.Provider) {
		if req.TTLSeconds != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "ttl_seconds is unsupported for connector rotation"))
			return
		}
		if idempotencyKey == "" {
			a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
			return
		}
		principal, err := requestPrincipalSubject(r.Context())
		if err != nil {
			a.writeError(w, err)
			return
		}
		bindingTenantID, ok := a.tenant(r)
		if !ok {
			a.writeProblem(w, problemUnauthorized())
			return
		}
		_, requestBinding, err := a.applicationSecretRequestBinding(
			bindingTenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(),
			"rotate", "rotation", req.Key, req)
		if err != nil {
			a.writeError(w, err)
			return
		}
		a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
			if tenantID != bindingTenantID {
				return 0, nil, errors.New("api: connector rotation binding tenant changed")
			}
			rep, err := a.executeConnectorApplicationSecretRotation(ctx, tenantID, idempotencyKey, requestBinding, req)
			if err != nil {
				return 0, nil, applicationSecretMutationError(err)
			}
			if rep.Queued {
				a.auditSecret(ctx, "secret.rotation.queued", tenantID, req.Key, 0)
			} else {
				a.auditSecret(ctx, "secret.rotation.completed", tenantID, req.Key, 0)
			}
			return http.StatusOK, toSecretRotationResponse(rep), nil
		})
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := unavailableDirectSecretRotationRequestBinding(principal, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	detail := manualStaticRotationUnavailableDetail
	if strings.HasPrefix(req.Provider, secretDynamicLeaseRotationPrefix) {
		detail = dynamicLeaseRotationUnavailableDetail
	}
	// This branch deliberately owns no independently durable receiver. Cache its
	// exact RFC 7807 refusal in the transactional recorder: retries cannot change
	// the command binding, but no durable "bound" recovery row can be stranded.
	a.mutateWithRecorder(w, r, idempotencyKey, binding, func(context.Context, string) (int, any, error) {
		return http.StatusServiceUnavailable, problem.New(http.StatusServiceUnavailable, detail), nil
	}, false)
}

// createSecretRotationSchedule records a tenant cadence for connector-backed
// application-secret rotation. Static providers are also refused by the manual
// route: their in-process phases have no durable ACK-loss receiver, so neither
// route can truthfully promise crash-safe execution.
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
		rotationRequest := secretRotationRequest{Provider: provider, Key: key, OldRef: oldRef}
		if isConnectorSecretRotation(provider) {
			targetID, _, err := connectorSecretRotationTarget(rotationRequest)
			if err != nil {
				return 0, nil, err
			}
			if a.secrets.syncTargets(tenantID)[targetID] == nil {
				return 0, nil, errStatus(http.StatusServiceUnavailable, connectorRotationTargetUnavailableDetail)
			}
		} else if strings.HasPrefix(provider, secretDynamicLeaseRotationPrefix) {
			return 0, nil, errStatus(http.StatusServiceUnavailable, dynamicLeaseRotationUnavailableDetail)
		} else {
			// Static rotators perform provider effects in the request process. A
			// schedule cannot safely resume an ACK-lost Stage/Cutover/Retire call,
			// so fail closed until a durable worker phase machine owns those calls.
			return 0, nil, errStatus(http.StatusServiceUnavailable, scheduledStaticRotationUnavailableDetail)
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

// runDueSecretRotationSchedules is the served connector scheduler tick for
// CAP-SECR-06. Each exact due edge first acquires a durable command receiver;
// only then may the event-sourced application-secret/outbox command run.
//
//trstctl:mutation
func (a *API) runDueSecretRotationSchedules(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	escapedPath := ""
	if r.URL != nil {
		escapedPath = r.URL.EscapedPath()
	}
	routeBinding, err := mutationRouteBinding(principal, r.Method, escapedPath)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var registration orchestrator.TenantRegistrationAuthority
	err = a.store.WithPrivacyRecoveryBarrier(
		r.Context(), tenantID, "secret rotation scheduler registration authority",
		func(barrierCtx context.Context) error {
			var resolveErr error
			registration, resolveErr = orchestrator.ResolveLiveTenantRegistrationAuthority(
				barrierCtx, a.secrets.be.EventLog, a.store, tenantID)
			return resolveErr
		})
	if err != nil {
		a.writeError(w, err)
		return
	}
	outerKey, requestBinding, err := secretRotationScheduleTickAuthority(
		tenantID, registration, idempotencyKey, routeBinding)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	const (
		runLimit          = 50
		scanLimit         = 500
		commandGCLimit    = 50
		tickLeaseDuration = 2 * time.Minute
	)
	ownerToken := events.NewID()
	recoveryCommandLeaseToken := events.NewID()
	var (
		tick       store.SecretRotationScheduleTick
		claimState store.SecretRotationScheduleTickClaimState
	)
	a.mutatePreparedDurableBound(
		w, r, outerKey, requestBinding,
		func(ctx context.Context, preparedTenantID string, tx pgx.Tx) (orchestrator.PreparedDurableEffectClaim, error) {
			if preparedTenantID != tenantID {
				return orchestrator.PreparedDurableEffectClaim{}, errors.New("api: scheduler tenant changed after registration resolution")
			}
			prepared, err := a.store.PrepareSecretRotationScheduleTickTx(
				ctx, tx, tenantID, outerKey, requestBinding,
				registration.EventID, registration.EventSequence, ownerToken,
				recoveryCommandLeaseToken, tickLeaseDuration)
			if err != nil {
				return orchestrator.PreparedDurableEffectClaim{}, err
			}
			tick = prepared.Tick
			claimState = prepared.State
			switch claimState {
			case store.SecretRotationScheduleTickSameKeyBusy:
				return orchestrator.PreparedDurableEffectClaim{}, errors.Join(
					errStatus(http.StatusServiceUnavailable, "this scheduler tick is already running; retry the same Idempotency-Key"),
					store.ErrSecretRotationScheduleTickInProgress,
					orchestrator.ErrInProgress,
				)
			case store.SecretRotationScheduleTickDifferentBusy:
				return orchestrator.PreparedDurableEffectClaim{}, errors.Join(
					errStatus(http.StatusServiceUnavailable, "another scheduler tick owns this tenant; retry after its bounded lease"),
					store.ErrSecretRotationScheduleTickInProgress,
				)
			case store.SecretRotationScheduleTickAcquired, store.SecretRotationScheduleTickTerminal:
			default:
				return orchestrator.PreparedDurableEffectClaim{}, fmt.Errorf(
					"%w: unknown scheduler tick claim state %q", store.ErrSecretRotationScheduleTickConflict, claimState)
			}
			return orchestrator.PreparedDurableEffectClaim{
				Completed: prepared.OuterCompleted, ResultCodec: prepared.ResultCodec,
				CompletedResult: prepared.ProtectedResult,
			}, nil
		},
		func(ctx context.Context, verifiedTenantID string, tx pgx.Tx, plaintext []byte) error {
			if verifiedTenantID != tenantID {
				return errors.New("api: scheduler tenant changed before terminal verification")
			}
			var cached cachedResponse
			if len(plaintext) == 0 || json.Unmarshal(plaintext, &cached) != nil ||
				!crypto.ConstantTimeEqual([]byte(cached.Binding), []byte(requestBinding)) {
				return fmt.Errorf("%w: outer scheduler result is not the exact bound response", store.ErrSecretRotationScheduleTickConflict)
			}
			return a.store.VerifySecretRotationScheduleTickTerminalTx(
				ctx, tx, tenantID, outerKey, requestBinding,
				registration.EventID, registration.EventSequence, cached.Status, cached.Body)
		},
		func(ctx context.Context, tenantID string) (int, any, error) {
			switch claimState {
			case store.SecretRotationScheduleTickTerminal:
				if tick.TerminalHTTPStatus == nil || len(tick.TerminalBody) == 0 || !json.Valid(tick.TerminalBody) {
					return 0, nil, fmt.Errorf("%w: terminal scheduler tick lacks canonical HTTP bytes", store.ErrSecretRotationScheduleTickConflict)
				}
				return *tick.TerminalHTTPStatus, json.RawMessage(append([]byte(nil), tick.TerminalBody...)), nil
			case store.SecretRotationScheduleTickAcquired:
			default:
				return 0, nil, fmt.Errorf("%w: unknown scheduler tick claim state %q", store.ErrSecretRotationScheduleTickConflict, claimState)
			}

			var resp secretRotationDueRunResponse
			if len(tick.Receipt) == 0 || json.Unmarshal(tick.Receipt, &resp) != nil ||
				resp.Runs == nil || resp.Deferred == nil || resp.Ran != tick.Ran || resp.Scanned != tick.Scanned {
				return 0, nil, fmt.Errorf("%w: retained scheduler progress is not a complete receipt", store.ErrSecretRotationScheduleTickConflict)
			}
			finalize := func(status int, commandRelease *store.SecretRotationScheduleCommandLeaseRelease) (int, any, error) {
				body, err := json.Marshal(resp)
				if err != nil {
					return 0, nil, err
				}
				terminal, err := a.store.FinalizeSecretRotationScheduleTick(
					ctx, tick, ownerToken, tick.OwnerGeneration, status, body, commandRelease)
				if err != nil {
					return 0, nil, err
				}
				if terminal.TerminalHTTPStatus == nil || *terminal.TerminalHTTPStatus != status ||
					len(terminal.TerminalBody) == 0 || !json.Valid(terminal.TerminalBody) {
					return 0, nil, fmt.Errorf("%w: finalized scheduler tick lacks exact terminal bytes", store.ErrSecretRotationScheduleTickConflict)
				}
				return status, json.RawMessage(append([]byte(nil), terminal.TerminalBody...)), nil
			}
			fail := func(scheduleID string, cause error, commandRelease *store.SecretRotationScheduleCommandLeaseRelease) (int, any, error) {
				markSecretRotationScheduleDueRunFailed(
					&resp, scheduleID, secretRotationScheduleSystemErrorDetail(cause))
				status, body, err := finalize(http.StatusServiceUnavailable, commandRelease)
				if err != nil {
					return 0, nil, errors.Join(cause, err)
				}
				return status, body, nil
			}

			for tick.Ran < runLimit && tick.Scanned < tick.SnapshotCount && tick.Scanned < scanLimit {
				var sched store.SecretRotationSchedule
				commandLeaseToken := ""
				if tick.CurrentSchedule != nil {
					sched = *tick.CurrentSchedule
					if tick.CurrentCommandLeaseToken == "" {
						return 0, nil, fmt.Errorf("%w: retained row snapshot is incomplete", store.ErrSecretRotationScheduleTickConflict)
					}
					commandLeaseToken = tick.CurrentCommandLeaseToken
				} else {
					var err error
					sched, err = a.store.GetSecretRotationScheduleTickRow(
						ctx, tenantID, tick.IdempotencyKey, tick.Scanned+1)
					if err != nil {
						return fail("", err, nil)
					}
					commandLeaseToken = events.NewID()
					tick, err = a.store.StartSecretRotationScheduleTickRow(
						ctx, tick, ownerToken, tick.OwnerGeneration, sched,
						commandLeaseToken, tickLeaseDuration)
					if err != nil {
						return 0, nil, err
					}
				}

				var (
					run            secretRotationScheduleRunResponse
					commandRelease *store.SecretRotationScheduleCommandLeaseRelease
					runErr         error
				)
				if sched.ConfigEventSequence == 0 {
					// Migration 0155 cannot invent the event sequence that created an
					// already-projected schedule. Consume and diagnose that immutable
					// snapshot row, but never claim a child command or call a provider.
					runErr = secretRotationScheduleDeferredError{
						reason: "config_revision_unanchored",
						cause:  errors.New("schedule configuration has no event revision; re-save the schedule before it can run"),
					}
				} else {
					run, commandRelease, runErr = a.runSecretRotationSchedule(
						ctx, tenantID, tick.IdempotencyKey, tick.Scanned+1, sched, commandLeaseToken)
				}
				if errors.Is(runErr, store.ErrSecretRotationScheduleDueEdgeStale) {
					// A retained terminal event already owns this exact frozen due edge.
				} else if reason, detail, deferred := secretRotationScheduleDeferredReason(runErr); deferred {
					resp.Deferred = append(resp.Deferred, secretRotationScheduleDeferredResponse{
						ScheduleID: sched.ID, Reason: reason, DueAt: sched.NextRunAt, Error: detail,
					})
				} else if runErr != nil {
					// The typed 503 is terminal for this outer key, not for the
					// row_started child. Cursor position and logical budgets stay put;
					// a new-key tick carries and reconciles this deterministic child.
					return fail(sched.ID, runErr, commandRelease)
				} else {
					resp.Runs = append(resp.Runs, run)
					resp.Ran++
				}
				resp.Scanned++
				progress, err := json.Marshal(resp)
				if err != nil {
					return 0, nil, err
				}
				tick, err = a.store.CompleteSecretRotationScheduleTickRow(
					ctx, tick, ownerToken, tick.OwnerGeneration, progress,
					resp.Ran, resp.Scanned, commandRelease, tickLeaseDuration)
				if err != nil {
					return 0, nil, err
				}
			}
			exhausted := tick.Scanned == tick.SnapshotCount
			// Exact-bound completion stays conservative: consuming all 50 runs or
			// 500 scans says another tick may be needed even if the last page was
			// short. Only an under-budget empty/short ring proves completion.
			resp.RunLimitReached = tick.Ran == runLimit
			resp.ScanLimitReached = tick.Scanned == scanLimit
			resp.Complete = exhausted && !resp.RunLimitReached && !resp.ScanLimitReached
			resp.Partial = false
			resp.FailedScheduleID = ""
			resp.SystemError = ""
			if _, err := a.orch.PurgeSecretRotationScheduleCommands(ctx, tenantID, commandGCLimit); err != nil {
				return fail("", err, nil)
			}
			return finalize(http.StatusOK, nil)
		})
}

func markSecretRotationScheduleDueRunFailed(
	resp *secretRotationDueRunResponse,
	scheduleID, systemError string,
) {
	resp.Complete = false
	resp.Partial = len(resp.Runs) > 0 || len(resp.Deferred) > 0
	resp.RunLimitReached = false
	resp.ScanLimitReached = false
	resp.FailedScheduleID = scheduleID
	resp.SystemError = systemError
}

type secretRotationScheduleDeferredError struct {
	reason string
	cause  error
}

func secretRotationScheduleTickAuthority(
	tenantID string,
	registration orchestrator.TenantRegistrationAuthority,
	rawIdempotencyKey, routeBinding string,
) (string, string, error) {
	if tenantID == "" || registration.EventID == "" || registration.EventSequence == 0 ||
		rawIdempotencyKey == "" || routeBinding == "" {
		return "", "", errors.New("scheduler tick requires a live registration, Idempotency-Key, and route binding")
	}
	rawKey := []byte(rawIdempotencyKey)
	rawKeyDigest := crypto.SHA256Hex(rawKey)
	secret.Wipe(rawKey)
	keyMaterial, err := json.Marshal(struct {
		Domain             string `json:"domain"`
		TenantID           string `json:"tenant_id"`
		RegistrationSeq    uint64 `json:"tenant_registration_event_sequence"`
		IdempotencyKeyHash string `json:"idempotency_key_sha256"`
	}{
		Domain: "trstctl.secret-rotation-schedule.tick-key.v3", TenantID: tenantID,
		RegistrationSeq:    registration.EventSequence,
		IdempotencyKeyHash: rawKeyDigest,
	})
	if err != nil {
		return "", "", err
	}
	defer secret.Wipe(keyMaterial)
	outerKey := rotationcommand.OuterKeyV3Prefix + crypto.SHA256Hex(keyMaterial)
	bindingMaterial, err := json.Marshal(struct {
		Domain          string `json:"domain"`
		TenantID        string `json:"tenant_id"`
		RegistrationSeq uint64 `json:"tenant_registration_event_sequence"`
		OuterKey        string `json:"outer_key"`
		RouteBinding    string `json:"route_binding"`
	}{
		Domain: "trstctl.secret-rotation-schedule.tick-binding.v3", TenantID: tenantID,
		RegistrationSeq: registration.EventSequence,
		OuterKey:        outerKey, RouteBinding: routeBinding,
	})
	if err != nil {
		return "", "", err
	}
	defer secret.Wipe(bindingMaterial)
	return outerKey, crypto.SHA256Hex(bindingMaterial), nil
}

func (e secretRotationScheduleDeferredError) Error() string {
	return secretRotationScheduleDeferredDetail(e.reason)
}
func (e secretRotationScheduleDeferredError) Unwrap() error { return e.cause }

func secretRotationScheduleDeferredReason(err error) (string, string, bool) {
	var deferred secretRotationScheduleDeferredError
	if !errors.As(err, &deferred) {
		return "", "", false
	}
	return deferred.reason, deferred.Error(), true
}

// secretRotationScheduleDeferredDetail returns only closed, bounded product
// language. The wrapped cause is kept for control flow and server logging, but
// provider/store text must never become a durable scheduler receipt.
func secretRotationScheduleDeferredDetail(reason string) string {
	return store.SecretRotationScheduleDeferredError(reason)
}

// secretRotationScheduleSystemErrorDetail deliberately does not render err.
// SQL constraint errors, custody backends, and wrapped connector failures can
// contain human-entered references or provider-controlled text. The receipt has
// stable schedule/run IDs for correlation; detailed causes stay in server logs.
func secretRotationScheduleSystemErrorDetail(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return store.SecretRotationScheduleTickInterruptedError
	}
	return store.SecretRotationScheduleTickProcessingError
}

// secretRotationScheduleTerminalErrorDetail admits only exact API details whose
// spelling is defined in this package. In particular, the connector worker's
// LastError is provider-controlled and is collapsed to a fixed delivery class.
func secretRotationScheduleTerminalErrorDetail(err error) string {
	if errors.Is(err, errTerminalConnectorRotationDelivery) {
		return connectorRotationDeliveryFailedDetail
	}
	if errors.Is(err, errTerminalApplicationSecretApproval) {
		return "application-secret approval is no longer usable"
	}
	var public *apiError
	if errors.As(err, &public) {
		switch public.detail {
		case "no such secret",
			"resource not found",
			"approval requester cannot approve their own request",
			"approval request expired",
			"approval request superseded",
			"approval authority already consumed",
			"approval target version or state drifted",
			"approval request has not reached quorum",
			connectorRotationDeliveryFailedDetail,
			connectorRotationTargetRequiredDetail,
			connectorRotationTargetUnavailableDetail,
			connectorRotationOldRefInvalidDetail,
			connectorRotationOldRefStaleDetail:
			return public.detail
		}
	}
	return "scheduled rotation failed"
}

// secretRotationScheduleContext replaces only the inner command identity. The
// HTTP middleware has already authenticated and authorized the run-due caller;
// the persisted enabled schedule is the non-human authority that must stay stable
// when another authorized runner takes over or the process restarts.
func secretRotationScheduleContext(ctx context.Context, tenantID string, sched store.SecretRotationSchedule) context.Context {
	authority := "secret-rotation-schedule:" + sched.ID
	ctx = context.WithValue(ctx, principalCtxKey, authz.Principal{TenantID: tenantID, Subject: authority})
	return events.ContextWithActor(ctx, events.Actor{Subject: authority})
}

func (a *API) runSecretRotationSchedule(
	ctx context.Context,
	tenantID string,
	tickIdempotencyKey string,
	tickOrdinal int,
	sched store.SecretRotationSchedule,
	leaseToken string,
) (secretRotationScheduleRunResponse, *store.SecretRotationScheduleCommandLeaseRelease, error) {
	if tickIdempotencyKey == "" || tickOrdinal <= 0 || leaseToken == "" {
		return secretRotationScheduleRunResponse{}, nil, fmt.Errorf("%w: scheduler child lease token is required", store.ErrSecretRotationScheduleCommandConflict)
	}
	ctx = secretRotationScheduleContext(ctx, tenantID, sched)
	runID := orchestrator.SecretRotationScheduleRunID(
		tenantID, sched.TenantRegistrationEventSequence, sched.ID, sched.NextRunAt)
	commandKey := orchestrator.SecretRotationScheduleCommandKey(runID)
	terminalEventID := orchestrator.SecretRotationScheduleRunEventID(runID)
	principal := "secret-rotation-schedule:" + sched.ID
	request := secretRotationRequest{Provider: sched.Provider, Key: sched.Key, OldRef: sched.OldRef}
	requestBinding, err := a.secretRotationScheduleRequestBinding(
		tenantID, principal, sched, commandKey, request)
	if err != nil {
		return secretRotationScheduleRunResponse{}, nil, err
	}
	command := store.SecretRotationScheduleCommand{
		TenantID: tenantID, IdentityVersion: sched.IdentityVersion,
		TenantRegistrationEventID:       sched.TenantRegistrationEventID,
		TenantRegistrationEventSequence: sched.TenantRegistrationEventSequence,
		ScheduleID:                      sched.ID, RunID: runID, DueAt: sched.NextRunAt,
		Provider: sched.Provider, Key: sched.Key, OldRef: sched.OldRef,
		IntervalSeconds: sched.IntervalSeconds, ConfigEventSequence: sched.ConfigEventSequence,
		TickIdempotencyKey: tickIdempotencyKey, TickOrdinal: tickOrdinal,
		CommandKey: commandKey, RequestBinding: requestBinding, TerminalEventID: terminalEventID,
	}
	claimed, acquired, err := a.store.ClaimSecretRotationScheduleCommand(
		ctx, command, leaseToken, time.Minute)
	if err != nil {
		return secretRotationScheduleRunResponse{}, nil, err
	}
	if !acquired {
		if claimed.ClaimState == store.SecretRotationScheduleCommandBusy && claimed.Status == "claimed" {
			return secretRotationScheduleRunResponse{}, nil, secretRotationScheduleDeferredError{
				reason: "command_claimed", cause: errors.New("another scheduler owns the durable due-edge command lease"),
			}
		}
		retained, found, reconcileErr := a.orch.ReconcileSecretRotationScheduleRun(
			ctx, tenantID, sched.ID, runID, sched.NextRunAt)
		if reconcileErr != nil {
			return secretRotationScheduleRunResponse{}, nil, reconcileErr
		}
		if !found {
			return secretRotationScheduleRunResponse{}, nil, fmt.Errorf(
				"%w: terminal command has no retained terminal event",
				store.ErrSecretRotationScheduleCommandConflict)
		}
		return secretRotationScheduleRunResponseFromReceipt(sched, retained, true), nil, nil
	}
	commandRelease := &store.SecretRotationScheduleCommandLeaseRelease{
		ScheduleID: sched.ID,
		RunID:      runID,
		LeaseToken: leaseToken,
	}
	if claimed.ClaimState == store.SecretRotationScheduleCommandRecovered {
		retained, found, reconcileErr := a.orch.ReconcileSecretRotationScheduleRun(
			ctx, tenantID, sched.ID, runID, sched.NextRunAt)
		if reconcileErr != nil {
			return secretRotationScheduleRunResponse{}, commandRelease, reconcileErr
		}
		if found {
			return secretRotationScheduleRunResponseFromReceipt(sched, retained, true), nil, nil
		}
		if claimed.PreparedAt != nil {
			retained, recordErr := a.orch.RecordSecretRotationScheduleRun(ctx, tenantID, store.SecretRotationScheduleRun{
				ScheduleID: sched.ID, RunID: runID,
				Status: claimed.PreparedStatus, NewRef: claimed.PreparedNewRef, Error: claimed.PreparedError,
				RanAt: *claimed.PreparedAt, TickIdempotencyKey: tickIdempotencyKey,
				TickOrdinal: tickOrdinal, LeaseToken: leaseToken,
			})
			if recordErr != nil {
				return secretRotationScheduleRunResponse{}, commandRelease, recordErr
			}
			return secretRotationScheduleRunResponseFromReceipt(sched, retained, true), nil, nil
		}
	} else if claimed.ClaimState != store.SecretRotationScheduleCommandCreated {
		return secretRotationScheduleRunResponse{}, commandRelease, fmt.Errorf(
			"%w: acquired command has unknown claim state %q",
			store.ErrSecretRotationScheduleCommandConflict, claimed.ClaimState)
	}

	status := "failed"
	errText := ""
	rep := rotation.Report{Key: sched.Key, OldRef: sched.OldRef}
	if isConnectorSecretRotation(sched.Provider) {
		rep, err = a.executeConnectorApplicationSecretRotation(ctx, tenantID, commandKey, requestBinding, request)
		if err != nil {
			if errors.Is(err, errPendingApplicationSecretApproval) {
				return secretRotationScheduleRunResponse{}, commandRelease, secretRotationScheduleDeferredError{
					reason: "approval_pending", cause: applicationSecretMutationError(err),
				}
			}
			if errors.Is(err, store.ErrApplicationSecretMutationInFlight) {
				return secretRotationScheduleRunResponse{}, commandRelease, secretRotationScheduleDeferredError{
					reason: "command_in_flight", cause: applicationSecretMutationError(err),
				}
			}
			if !isTerminalConnectorRotationScheduleError(err) {
				// Shared store/event/custody and integrity failures fail-stop the tick.
				return secretRotationScheduleRunResponse{}, commandRelease, applicationSecretMutationError(err)
			}
			// A stale source or connector configuration is terminal for this due edge,
			// not for the whole tenant batch. Persist the failure below and retry only
			// at the bounded next cadence so one broken schedule cannot starve newer work.
			err = applicationSecretMutationError(err)
		}
	} else {
		// Rows created before the connector-only contract may still name an
		// in-process static or dynamic provider. They execute no provider phase:
		// a terminal unsupported event advances and disables the schedule.
		status = "unsupported"
		if strings.HasPrefix(sched.Provider, secretDynamicLeaseRotationPrefix) {
			errText = dynamicLeaseRotationUnavailableDetail
		} else {
			errText = scheduledStaticRotationUnavailableDetail
		}
	}
	if err != nil {
		errText = secretRotationScheduleTerminalErrorDetail(err)
		if rep.RollbackFailed {
			status = "rollback_failed"
		} else if rep.RollbackAttempted && rep.RolledBack {
			status = "rolled_back"
		} else if rep.FailedPhase == "retire" && rep.NewRef != "" {
			// Cutover and verification committed the live successor. The next
			// cadence must start from it even though predecessor cleanup is pending.
			status = "retire_pending"
		} else if rep.FailedPhase == "delivery" && rep.NewRef != "" {
			// The canonical application-secret version committed before the worker
			// exhausted delivery. Preserve that explicit phase as advancement proof.
			status = "delivery_failed"
		}
	} else if status == "unsupported" {
		// The explicit terminal classification above is already authoritative.
	} else if rep.Completed {
		status = "completed"
	} else if rep.Queued {
		status = "queued"
	}
	rotationResp := toSecretRotationResponse(rep)
	if rotationResp.RollbackError != "" {
		rotationResp.RollbackError = store.SecretRotationScheduleRollbackError
	}
	rotationResp.Error = errText
	run, err := a.orch.RecordSecretRotationScheduleRun(ctx, tenantID, store.SecretRotationScheduleRun{
		ScheduleID: sched.ID, RunID: runID, Status: status, NewRef: rep.NewRef, Error: errText,
		TickIdempotencyKey: tickIdempotencyKey, TickOrdinal: tickOrdinal, LeaseToken: leaseToken,
	})
	if err != nil {
		return secretRotationScheduleRunResponse{}, commandRelease, err
	}
	if status == "completed" {
		a.auditSecret(ctx, "secret.rotation_schedule.completed", tenantID, sched.Key, 0)
	} else if status == "queued" {
		a.auditSecret(ctx, "secret.rotation_schedule.queued", tenantID, sched.Key, 0)
	}
	result := secretRotationScheduleRunResponseFromReceipt(sched, run, false)
	if run.Status != "unsupported" {
		result.Rotation = rotationResp
		result.Rotation.NewRef = run.NewRef
		result.Rotation.Error = run.Error
	}
	result.Status = run.Status
	result.Error = run.Error
	return result, nil, nil
}

func (a *API) secretRotationScheduleRequestBinding(
	tenantID, principal string,
	sched store.SecretRotationSchedule,
	commandKey string,
	request secretRotationRequest,
) (string, error) {
	if isConnectorSecretRotation(sched.Provider) {
		_, baseBinding, err := a.applicationSecretRequestBinding(
			tenantID, commandKey, principal, "SCHEDULE",
			"/api/v1/secrets/rotation-schedules/"+sched.ID,
			"rotate", "rotation", sched.Key, request)
		if err != nil {
			return "", err
		}
		canonical, err := json.Marshal(struct {
			Domain          string `json:"domain"`
			RegistrationSeq uint64 `json:"tenant_registration_event_sequence"`
			BaseBinding     string `json:"base_binding"`
		}{
			Domain:          "trstctl.secret-rotation-schedule.child-binding.v3",
			RegistrationSeq: sched.TenantRegistrationEventSequence,
			BaseBinding:     baseBinding,
		})
		if err != nil {
			return "", err
		}
		defer secret.Wipe(canonical)
		return crypto.SHA256Hex(canonical), nil
	}
	canonical, err := json.Marshal(struct {
		Domain          string    `json:"domain"`
		TenantID        string    `json:"tenant_id"`
		RegistrationSeq uint64    `json:"tenant_registration_event_sequence"`
		ScheduleID      string    `json:"schedule_id"`
		DueAt           time.Time `json:"due_at"`
		Provider        string    `json:"provider"`
		Key             string    `json:"key"`
		OldRef          string    `json:"old_ref"`
		CommandKey      string    `json:"command_key"`
	}{
		"trstctl.secret-rotation-schedule.child-binding.v3", tenantID,
		sched.TenantRegistrationEventSequence, sched.ID, sched.NextRunAt.UTC(),
		sched.Provider, sched.Key, sched.OldRef, commandKey,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(canonical)
	return crypto.SHA256Hex(canonical), nil
}

func secretRotationScheduleRunResponseFromReceipt(
	sched store.SecretRotationSchedule,
	run store.SecretRotationScheduleRun,
	reconciled bool,
) secretRotationScheduleRunResponse {
	closedError := store.CanonicalSecretRotationScheduleError(run.Status, run.Error)
	rep := rotation.Report{Key: sched.Key, OldRef: sched.OldRef, NewRef: run.NewRef}
	switch run.Status {
	case "completed":
		rep.Completed = true
	case "queued":
		rep.Queued = true
	case "rolled_back":
		rep.RollbackAttempted = true
		rep.RolledBack = true
	case "rollback_failed":
		rep.RollbackAttempted = true
		rep.RollbackFailed = true
	case "retire_pending":
		rep.FailedPhase = "retire"
	case "delivery_failed":
		rep.FailedPhase = "delivery"
	case "unsupported":
		rep.FailedPhase = "provider"
	}
	rotationResp := toSecretRotationResponse(rep)
	rotationResp.Error = closedError
	return secretRotationScheduleRunResponse{
		ScheduleID: sched.ID, RunID: run.RunID, DueAt: run.DueAt, Status: run.Status,
		Rotation: rotationResp, Error: closedError, RanAt: run.RanAt, Reconciled: reconciled,
	}
}

const (
	secretConnectorRotationPrefix            = "connector:"
	secretDynamicLeaseRotationPrefix         = "dynamic-lease:"
	connectorRotationTargetRequiredDetail    = "connector rotation target is required"
	connectorRotationTargetUnavailableDetail = "secret sync target is not configured"
	connectorRotationOldRefInvalidDetail     = "connector rotation old_ref must be version:<n>"
	connectorRotationOldRefStaleDetail       = "connector rotation old_ref does not name the current version"
	connectorRotationDeliveryFailedDetail    = "connector delivery failed"
	dynamicLeaseRotationUnavailableDetail    = "dynamic-lease rotation is unavailable until its issue, delivery, and predecessor retirement phases share one durable worker command"
	manualStaticRotationUnavailableDetail    = "manual static-provider rotation is unavailable until a durable worker owns stage, cutover, verification, rollback, and retirement"
	scheduledStaticRotationUnavailableDetail = "scheduled static-provider rotation is unavailable until a durable worker owns stage, cutover, verification, rollback, and retirement"
)

var errTerminalConnectorRotationDelivery = errors.New("api: connector rotation delivery is terminal")

func isConnectorSecretRotation(provider string) bool {
	provider = strings.TrimSpace(provider)
	return strings.HasPrefix(provider, secretConnectorRotationPrefix) &&
		strings.TrimSpace(strings.TrimPrefix(provider, secretConnectorRotationPrefix)) != ""
}

func unavailableDirectSecretRotationRequestBinding(principal string, req secretRotationRequest) (string, error) {
	operation := "static-secret.rotation.unavailable"
	if strings.HasPrefix(req.Provider, secretDynamicLeaseRotationPrefix) {
		// Preserve the existing binding domain for already-attempted dynamic-lease
		// commands; the static refusal joins the same shape under a disjoint domain.
		operation = "dynamic-secret.rotation"
	}
	canonical := struct {
		Operation  string `json:"operation"`
		Principal  string `json:"principal"`
		Provider   string `json:"provider"`
		Role       string `json:"role"`
		OldRef     string `json:"old_ref"`
		Target     string `json:"target"`
		RemoteKey  string `json:"remote_key"`
		TTLSeconds *int   `json:"ttl_seconds,omitempty"`
	}{
		Operation: operation, Principal: principal,
		Provider: req.Provider, Role: req.Key, OldRef: req.OldRef,
		Target: req.Target, RemoteKey: req.RemoteKey, TTLSeconds: req.TTLSeconds,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}

func isTerminalConnectorRotationScheduleError(err error) bool {
	if errors.Is(err, store.ErrSecretNotFound) || errors.Is(err, errTerminalApplicationSecretApproval) ||
		errors.Is(err, errTerminalConnectorRotationDelivery) {
		return true
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.detail {
	case connectorRotationTargetRequiredDetail,
		connectorRotationTargetUnavailableDetail,
		connectorRotationOldRefInvalidDetail,
		connectorRotationOldRefStaleDetail:
		return true
	default:
		return false
	}
}

func connectorSecretRotationTarget(req secretRotationRequest) (targetID, remoteKey string, err error) {
	targetID = strings.TrimSpace(req.Target)
	if strings.HasPrefix(req.Provider, secretConnectorRotationPrefix) {
		targetID = strings.TrimSpace(strings.TrimPrefix(req.Provider, secretConnectorRotationPrefix))
	}
	if targetID == "" {
		return "", "", errStatus(http.StatusBadRequest, connectorRotationTargetRequiredDetail)
	}
	remoteKey = strings.TrimSpace(req.RemoteKey)
	if remoteKey == "" {
		remoteKey = strings.TrimSpace(req.Key)
	}
	return targetID, remoteKey, nil
}

func connectorRotationSyncAAD(tenantID, target, id, key string) []byte {
	return []byte(tenantID + "/secret-sync/" + target + "/" + id + "/" + key)
}

// executeConnectorApplicationSecretRotation turns the connector path into one
// canonical application-secret command. The projector changes secret_store and
// writes the sealed delivery job/outbox in the same PostgreSQL transaction. Only
// the outbox worker contacts the connector; request handling returns the durable
// queued result and never performs a second compensating secret write.
func (a *API) executeConnectorApplicationSecretRotation(
	ctx context.Context,
	tenantID, idempotencyKey, requestBinding string,
	req secretRotationRequest,
) (rotation.Report, error) {
	targetID, remoteKey, err := connectorSecretRotationTarget(req)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	oldVersion, err := parseSecretVersionRef(req.OldRef)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	tenantEpoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	key := []byte(idempotencyKey)
	keyDigest := crypto.SHA256Hex(key)
	secret.Wipe(key)
	eventID := applicationSecretMutationEventID(tenantID, tenantEpoch, req.Key, "rotate", keyDigest)
	if receipt, ok, receiptErr := a.applicationSecretMaterializedResult(
		ctx, tenantID, eventID, requestBinding, req.Key, "rotate"); receiptErr != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, receiptErr
	} else if ok {
		return a.connectorApplicationSecretRotationReport(ctx, tenantID, eventID,
			req.Key, req.OldRef, receipt.ResultVersion)
	}
	target := a.secrets.syncTargets(tenantID)[targetID]
	if target == nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef},
			errStatus(http.StatusServiceUnavailable, connectorRotationTargetUnavailableDetail)
	}
	fence, payload, prepared, err := a.applicationSecretMutationFence(
		ctx, tenantID, req.Key, "rotate", eventID, requestBinding)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Key)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, store.ErrSecretNotFound
		}
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	if current.Version != oldVersion {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef},
			errStatus(http.StatusConflict, connectorRotationOldRefStaleDetail)
	}
	if !prepared {
		random, randomErr := crypto.RandomBytes(32)
		if randomErr != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, randomErr
		}
		value := make([]byte, 0, len("rotated-")+hex.EncodedLen(len(random)))
		value = append(value, "rotated-"...)
		encoded := make([]byte, hex.EncodedLen(len(random)))
		hex.Encode(encoded, random)
		value = append(value, encoded...)
		secret.Wipe(encoded)
		secret.Wipe(random)
		defer secret.Wipe(value)

		commandKeyDigest, commandEvidence, commandErr := a.applicationSecretCommandEvidence(
			tenantID, idempotencyKey, canonicalApplicationSecretCommand{
				Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: tenantEpoch,
				Action: "rotate", Name: req.Key, Surface: "rotation", Provider: req.Provider,
				Target: targetID, RemoteKey: remoteKey, OldRef: req.OldRef,
				ExpectedVersion: current.Version, ResultVersion: current.Version + 1, Value: value,
			})
		if commandErr != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, commandErr
		}
		if commandKeyDigest != keyDigest {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, errors.New("api: connector rotation idempotency digest changed")
		}
		sealed, sealErr := a.secrets.seal(ctx, tenantID, value, sealAAD(tenantID, req.Key))
		if sealErr != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, sealErr
		}
		jobID := store.DurableSecretSyncJobID(tenantID, eventID)
		syncSealed, sealErr := a.secrets.seal(ctx, tenantID, value,
			connectorRotationSyncAAD(tenantID, targetID, jobID, remoteKey))
		if sealErr != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, sealErr
		}
		payload = projections.ApplicationSecretMutation{
			TenantEpoch: tenantEpoch, Action: "rotate", Name: req.Key,
			ExpectedVersion: current.Version, ResultVersion: current.Version + 1, Sealed: sealed,
			IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
			CommandEvidence: commandEvidence, Surface: "rotation",
			Sync: &projections.SecretSyncQueued{
				ID: jobID, SecretName: req.Key, SecretVersion: int64(current.Version + 1),
				Target: targetID, RemoteKey: remoteKey, ValueDigest: crypto.SHA256Hex(value),
				IdempotencyKey: store.SecretSyncOutboxIdempotencyKey(targetID, jobID),
				RequestBinding: requestBinding, Sealed: syncSealed,
			},
		}
		fence, payload, err = a.claimApplicationSecretMutationFence(ctx, tenantID, req.Key,
			"rotate", eventID, projections.EventApplicationSecretRotated, requestBinding, payload)
		if err != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
		}
	}
	fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, tenantID, fence, payload)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	_, canonical, err := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	if canonical.Sync == nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, errors.New("api: connector rotation canonical event omitted sync intent")
	}
	// The API commits only the canonical event + projected sync intent. The bounded
	// outbox worker is the sole owner of the external connector call (AN-6).
	return a.connectorApplicationSecretRotationReport(ctx, tenantID, eventID,
		req.Key, req.OldRef, canonical.ResultVersion)
}

func (a *API) connectorApplicationSecretRotationReport(
	ctx context.Context,
	tenantID, eventID, key, oldRef string,
	resultVersion int,
) (rotation.Report, error) {
	report := rotation.Report{
		Key: key, OldRef: oldRef, NewRef: "version:" + strconv.Itoa(resultVersion),
	}
	jobID := store.DurableSecretSyncJobID(tenantID, eventID)
	job, err := a.secrets.be.Store.GetSecretSyncJob(ctx, tenantID, jobID)
	if err != nil {
		return report, fmt.Errorf("api: load connector rotation delivery job: %w", err)
	}
	switch job.Status {
	case store.SecretSyncJobPending:
		report.Queued = true
	case store.SecretSyncJobDelivered:
		report.Completed = true
	case store.SecretSyncJobFailed:
		report.FailedPhase = "delivery"
		// LastError is provider-controlled operational diagnostics. Collapse it at
		// this boundary so neither the direct mutation response nor the durable
		// scheduler receipts can accidentally serialize it.
		return report, errTerminalConnectorRotationDelivery
	default:
		return report, fmt.Errorf("api: connector rotation delivery job has invalid status %q", job.Status)
	}
	return report, nil
}

func parseSecretVersionRef(ref string) (int, error) {
	const prefix = "version:"
	if !strings.HasPrefix(ref, prefix) {
		return 0, errStatus(http.StatusBadRequest, connectorRotationOldRefInvalidDetail)
	}
	version, err := strconv.Atoi(strings.TrimPrefix(ref, prefix))
	if err != nil || version <= 0 {
		return 0, errStatus(http.StatusBadRequest, connectorRotationOldRefInvalidDetail)
	}
	return version, nil
}

type secretVisibilitySourceCounts struct {
	Repository int
	ThirdParty int
	Cloud      int
}

// importSecrets reserves the compatibility route but fails closed. The former
// implementation wrote the derived secret table directly; serving that behavior
// would violate AN-2 until an atomic batch event/fence/receipt schema exists.
//
//trstctl:mutation
func (a *API) importSecrets(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeSecretImportRequest(r)
		if err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		defer wipeSecretImportRequest(&req)
		if len(req.Values) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "values must contain at least one secret")
		}
		// The legacy bulk path wrote secret_store directly, so a successful response
		// could not be rebuilt from immutable history (AN-2). Keep the route honest and
		// fail closed until a future batch-command schema can atomically fence, append,
		// project, and receipt every imported name.
		return 0, nil, errStatus(http.StatusNotImplemented,
			"bulk secret import is unavailable until event-sourced atomic batch import is configured")
	})
}

func decodeSecretImportRequest(r *http.Request) (req secretImportRequest, err error) {
	// json.Decoder may populate earlier map entries before rejecting a later value
	// or a second JSON document. Install cleanup before Decode so those partial
	// secret allocations are zeroed on every error exit (AN-8).
	defer func() {
		if err != nil {
			wipeSecretImportRequest(&req)
		}
	}()
	err = decodeJSON(r, &req)
	return req, err
}

func wipeSecretImportRequest(req *secretImportRequest) {
	if req == nil {
		return
	}
	for key, value := range req.Values {
		value.wipe()
		delete(req.Values, key)
	}
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
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	bindingTenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	keyDigest, requestBinding, err := a.applicationSecretRequestBinding(
		bindingTenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(), "delete", "native", name, nil)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if tenantID != bindingTenantID {
			return 0, nil, errors.New("api: application-secret binding tenant changed")
		}
		tenantEpoch, epochErr := a.applicationSecretTenantEpoch(ctx, tenantID)
		if epochErr != nil {
			return 0, nil, epochErr
		}
		eventID := applicationSecretMutationEventID(tenantID, tenantEpoch, name, "delete", keyDigest)
		if _, ok, receiptErr := a.applicationSecretMaterializedResult(
			ctx, tenantID, eventID, requestBinding, name, "delete"); receiptErr != nil {
			return 0, nil, applicationSecretMutationError(receiptErr)
		} else if ok {
			return http.StatusNoContent, nil, nil
		}
		fence, payload, prepared, err := a.applicationSecretMutationFence(
			ctx, tenantID, name, "delete", eventID, requestBinding)
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
		current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such secret")
			}
			return 0, nil, err
		}
		if !prepared {
			commandKeyDigest, commandEvidence, commandErr := a.applicationSecretCommandEvidence(tenantID, idempotencyKey, canonicalApplicationSecretCommand{
				Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: tenantEpoch, Action: "delete",
				Name: name, Surface: "native", ExpectedVersion: current.Version,
			})
			if commandErr != nil {
				return 0, nil, commandErr
			}
			if commandKeyDigest != keyDigest {
				return 0, nil, errors.New("api: application-secret idempotency digest changed")
			}
			payload = projections.ApplicationSecretMutation{
				TenantEpoch: tenantEpoch, Action: "delete", Name: name, ExpectedVersion: current.Version,
				IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
				CommandEvidence: commandEvidence, Surface: "native",
			}
			fence, payload, err = a.claimApplicationSecretMutationFence(ctx, tenantID, name,
				"delete", eventID, projections.EventApplicationSecretDeleted, requestBinding, payload)
			if err != nil {
				return 0, nil, applicationSecretMutationError(err)
			}
		}
		fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, tenantID, fence, payload)
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
		if _, _, err := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload); err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
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

func toSecretRotationResponse(rep rotation.Report) secretRotationResponse {
	return secretRotationResponse{
		Key: rep.Key, OldRef: rep.OldRef, NewRef: rep.NewRef, Completed: rep.Completed,
		Queued:     rep.Queued,
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
		LastRunStatus: s.LastRunStatus, LastNewRef: s.LastNewRef,
		LastError: store.CanonicalSecretRotationScheduleError(s.LastRunStatus, s.LastError),
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
