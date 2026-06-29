package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gouuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/leaseworker"
	"trstctl.com/trstctl/internal/pkisecret"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/secretsdk"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
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
	// KEK wraps each stored secret's data key (envelope encryption at rest). A
	// LocalKEK or an HSM/KMS seal.KeyWrapper satisfies it. Required.
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
	// SecretSyncOutbox returns the tenant/target durable outbox used before any
	// external sync write is attempted (AN-6). The server wires this to the sealed
	// PostgreSQL outbox; embedders may supply their own.
	SecretSyncOutbox func(tenantID, target string) secretsync.Outbox
	// SecretScanner invokes the configured code/CI secret scanner. The served binary
	// wires this to a Gitleaks subprocess runner; nil leaves POST /secrets/scans
	// fail-closed while the rest of the secrets surface remains available.
	SecretScanner SecretScanner
}

// SecretScanner is the process boundary used by POST /api/v1/secrets/scans.
// Implementations must return metadata only; secret values stay inside the scanner
// process and redacted report file.
type SecretScanner interface {
	Scan(ctx context.Context, path string) (secretscan.Report, error)
}

type secretRepoScanProviderResponse struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	RealtimeTriggers []string `json:"realtime_triggers"`
	AuthMode         string   `json:"auth_mode"`
	IngestMode       string   `json:"ingest_mode"`
	RefTypes         []string `json:"ref_types"`
	SecretHandling   string   `json:"secret_handling"`
	OutboxMode       string   `json:"outbox_mode"`
}

type secretRepoScanGateResponse struct {
	ID       string `json:"id"`
	Command  string `json:"command"`
	Artifact string `json:"artifact"`
	Required bool   `json:"required"`
}

type secretRepoScanWebhookRequest struct {
	Repository    string `json:"repository"`
	CloneURL      string `json:"clone_url,omitempty"`
	CheckoutPath  string `json:"checkout_path,omitempty"`
	Ref           string `json:"ref,omitempty"`
	CommitSHA     string `json:"commit_sha,omitempty"`
	Event         string `json:"event,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
}

type secretRepoScanWebhookResponse struct {
	Capability        string `json:"capability"`
	Provider          string `json:"provider"`
	Repository        string `json:"repository"`
	SourceID          string `json:"source_id"`
	RunID             string `json:"run_id"`
	Queued            bool   `json:"queued"`
	Status            string `json:"status"`
	OutboxDestination string `json:"outbox_destination"`
	Scanner           string `json:"scanner"`
	DiscoveryRunPath  string `json:"discovery_run_path"`
}

type secretRepoScanPostureResponse struct {
	Capability           string                           `json:"capability"`
	Served               bool                             `json:"served"`
	GeneratedAt          string                           `json:"generated_at"`
	Providers            []secretRepoScanProviderResponse `json:"providers"`
	WebhookPaths         []string                         `json:"webhook_paths"`
	QueueModel           string                           `json:"queue_model"`
	Scanner              string                           `json:"scanner"`
	MinimumRulesActive   int                              `json:"minimum_rules_active"`
	RedactionModel       string                           `json:"redaction_model"`
	EventFlow            []string                         `json:"event_flow"`
	ReleaseGates         []secretRepoScanGateResponse     `json:"release_gates"`
	OperatorActions      []string                         `json:"operator_actions"`
	Residuals            []string                         `json:"residuals"`
	EvidenceRefs         []string                         `json:"evidence_refs"`
	ArchitectureControls []string                         `json:"architecture_controls"`
}

// secretsService is the assembled served secrets surface. It owns the per-request
// construction of the tenant-scoped frameworks (AN-1) and the dynamic lease engines.
// One-time share links are durable rows in PostgreSQL, not process memory, so valid
// shares survive an API restart.
type secretsService struct {
	be SecretsBackend

	mu     sync.Mutex
	leases map[string]*dynsecret.Engine // tenant -> dynamic lease engine
}

// WithSecrets mounts the served secrets/identity surface (GAP-006). The KEK, store,
// and audit sink are required; the issuing CA + auth secret are optional and gate
// their sub-features. When unset, the /api/v1/secrets/* routes fail closed with a
// clear "not enabled" problem.
func WithSecrets(be SecretsBackend) Option {
	return func(c *config) {
		c.secrets = &secretsService{
			be: be, leases: map[string]*dynsecret.Engine{},
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
	Provider string `json:"provider"`
	Key      string `json:"key"`
	OldRef   string `json:"old_ref"`
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

type secretSyncRequest struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	RemoteKey string `json:"remote_key"`
}

type secretSyncResponse struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	RemoteKey string `json:"remote_key"`
	Enqueued  bool   `json:"enqueued"`
	Delivered bool   `json:"delivered"`
}

type secretScanRequest struct {
	Path string `json:"path"`
}

type secretScanFindingResponse struct {
	RuleID        string `json:"rule_id"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	CredentialRef string `json:"credential_ref"`
}

type secretScanResponse struct {
	RunID         string                      `json:"run_id"`
	Scanner       string                      `json:"scanner"`
	EngineVersion string                      `json:"engine_version"`
	RulesActive   int                         `json:"rules_active"`
	FindingsCount int                         `json:"findings_count"`
	Findings      []secretScanFindingResponse `json:"findings"`
}

type dynamicLeaseIssueRequest struct {
	Provider   string `json:"provider"`
	Role       string `json:"role"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type dynamicLeaseRenewRequest struct {
	ExtendSeconds int `json:"extend_seconds"`
}

type dynamicLeaseResponse struct {
	ID         string          `json:"id"`
	Provider   string          `json:"provider"`
	Role       string          `json:"role"`
	State      string          `json:"state"`
	Credential secretJSONBytes `json:"credential,omitempty"`
	IssuedAt   time.Time       `json:"issued_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
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
		sealed, err := seal.Seal(a.secrets.be.KEK, []byte(req.Value), sealAAD(tenantID, req.Name))
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
	value, err := seal.Open(a.secrets.be.KEK, rec.Sealed, sealAAD(tenantID, name))
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
		sealed, err := seal.Seal(a.secrets.be.KEK, []byte(req.Value), sealAAD(tenantID, name))
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
		rotator := a.secrets.be.SecretRotators[req.Provider]
		if rotator == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret rotation provider is not configured")
		}
		engine := rotation.New(tenantID, rotator, a.secrets.be.Audit)
		rep, err := engine.Rotate(ctx, req.Key, req.OldRef)
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

// syncSecret pushes a stored secret to a configured external target. The secret value
// is read internally, enqueued through the sync outbox first (AN-6), delivered by the
// pusher, and wiped before the metadata-only response is returned.
//
//trstctl:mutation
func (a *API) syncSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretSyncRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Name = strings.TrimSpace(req.Name)
		req.Target = strings.TrimSpace(req.Target)
		req.RemoteKey = strings.TrimSpace(req.RemoteKey)
		if req.Name == "" || req.Target == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name and target are required")
		}
		if req.RemoteKey == "" {
			req.RemoteKey = req.Name
		}
		target := a.secrets.be.SecretSyncTargets[req.Target]
		if target == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret sync target is not configured")
		}
		if a.secrets.be.SecretSyncOutbox == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret sync outbox is not configured")
		}
		rec, err := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Name)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such secret")
			}
			return 0, nil, err
		}
		value, err := seal.Open(a.secrets.be.KEK, rec.Sealed, sealAAD(tenantID, req.Name))
		if err != nil {
			return 0, nil, err
		}
		defer secret.Wipe(value)
		outbox := a.secrets.be.SecretSyncOutbox(tenantID, req.Target)
		engine := secretsync.New(tenantID, target, outbox, a.secrets.be.Audit)
		if err := engine.Sync(ctx, req.RemoteKey, value); err != nil {
			return 0, nil, err
		}
		delivered, err := engine.RunDeliveries(ctx)
		if err != nil {
			return 0, nil, err
		}
		a.auditSecret(ctx, "secret.sync.requested", tenantID, req.Name, rec.Version)
		return http.StatusOK, secretSyncResponse{
			Name: req.Name, Target: req.Target, RemoteKey: req.RemoteKey,
			Enqueued: true, Delivered: delivered > 0,
		}, nil
	})
}

// scanSecrets invokes the configured Gitleaks binary through the served API and
// records redacted metadata into discovery findings. The scanner output is parsed
// for rule/file/line only; the secret value is neither read nor persisted.
//
//trstctl:mutation
func (a *API) scanSecrets(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, secretsDisabledProblem()
		}
		if a.secrets.be.SecretScanner == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret scanner is not configured")
		}
		var req secretScanRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(req.Path) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "path is required")
		}

		start := time.Now()
		report, err := a.secrets.be.SecretScanner.Scan(ctx, req.Path)
		a.observeFeature("secrets", "scan", start, err)
		if err != nil {
			switch {
			case errors.Is(err, secretscan.ErrInvalidScanTarget):
				return 0, nil, errStatus(http.StatusBadRequest, err.Error())
			case errors.Is(err, secretscan.ErrGitleaksBinaryNotFound):
				return 0, nil, errStatus(http.StatusServiceUnavailable, "gitleaks binary is not configured")
			default:
				return 0, nil, errStatus(http.StatusBadGateway, err.Error())
			}
		}
		if report.RulesActive < secretscan.GitleaksMinRulesActive {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "gitleaks rule set is below the required 140-rule floor")
		}

		rows, findings, err := discoveryFindingsFromSecretScan(report)
		if err != nil {
			return 0, nil, err
		}
		run, _, _, err := a.orch.RecordSecretScan(ctx, tenantID, report.Scanner, req.Path, report.RulesActive, rows)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, secretScanResponse{
			RunID:         run.ID,
			Scanner:       report.Scanner,
			EngineVersion: report.EngineVersion,
			RulesActive:   report.RulesActive,
			FindingsCount: len(findings),
			Findings:      findings,
		}, nil
	})
}

func discoveryFindingsFromSecretScan(report secretscan.Report) ([]store.DiscoveryFinding, []secretScanFindingResponse, error) {
	rows := make([]store.DiscoveryFinding, 0, len(report.Findings))
	out := make([]secretScanFindingResponse, 0, len(report.Findings))
	for _, f := range report.Findings {
		if strings.TrimSpace(f.RuleID) == "" || strings.TrimSpace(f.File) == "" {
			continue
		}
		ref := f.CredentialRef
		if ref == "" {
			ref = f.RuleID + "@" + f.File
		}
		meta, err := json.Marshal(map[string]any{
			"scanner":        report.Scanner,
			"engine_version": report.EngineVersion,
			"rule_id":        f.RuleID,
			"file":           f.File,
			"line":           f.Line,
			"rules_active":   report.RulesActive,
		})
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, store.DiscoveryFinding{
			Kind:        "leaked_secret",
			Ref:         ref,
			Provenance:  report.Scanner + ":" + f.File,
			Fingerprint: firstNonEmptyString(f.Fingerprint, ref),
			RiskScore:   95,
			Metadata:    json.RawMessage(meta),
		})
		out = append(out, secretScanFindingResponse{RuleID: f.RuleID, File: f.File, Line: f.Line, CredentialRef: ref})
	}
	return rows, out, nil
}

func (a *API) secretRepoScanPosture(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildSecretRepoScanPosture(time.Now().UTC().Format(time.RFC3339)))
}

// receiveSecretRepoWebhook is the normalized GitHub/GitLab/Bitbucket realtime
// repository secret-scan ingress. It does not clone or call providers inline:
// the mutation records a tenant-scoped discovery source/run and the existing
// discovery.run outbox worker performs checkout + Gitleaks (AN-2/AN-6).
//
//trstctl:mutation
func (a *API) receiveSecretRepoWebhook(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	provider := normalizeSecretRepoProvider(r.PathValue("provider"))
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, secretsDisabledProblem()
		}
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret repository scan queue is not configured")
		}
		if provider == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "provider must be github, gitlab, or bitbucket")
		}
		var req secretRepoScanWebhookRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		cfg, err := secretRepoScanConfig(provider, req)
		if err != nil {
			return 0, nil, err
		}
		body, err := json.Marshal(cfg)
		if err != nil {
			return 0, nil, err
		}
		sourceID := secretRepoSourceID(tenantID, cfg)
		src, err := a.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
			ID:     sourceID,
			Kind:   secretscan.RepositorySourceKind,
			Name:   secretRepoSourceName(cfg),
			Config: body,
		})
		if err != nil {
			return 0, nil, err
		}
		run, err := a.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
			SourceID: src.ID,
			DryRun:   false,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, secretRepoScanWebhookResponse{
			Capability:        "CAP-SCAN-01",
			Provider:          cfg.Provider,
			Repository:        cfg.Repository,
			SourceID:          src.ID,
			RunID:             run.ID,
			Queued:            true,
			Status:            run.Status,
			OutboxDestination: "discovery.run",
			Scanner:           "gitleaks " + secretscan.GitleaksPinnedVersion,
			DiscoveryRunPath:  "/api/v1/discovery/runs/" + run.ID,
		}, nil
	})
}

func buildSecretRepoScanPosture(generatedAt string) secretRepoScanPostureResponse {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	providers := []secretRepoScanProviderResponse{
		{
			ID:               "github",
			Name:             "GitHub",
			RealtimeTriggers: []string{"push", "pull_request", "workflow_run", "repository_dispatch"},
			AuthMode:         "authenticated trstctl SecretsWrite webhook; GitHub App token is referenced by credential_ref for private clone follow-up",
			IngestMode:       "POST normalized GitHub event enqueues a secret_repo discovery run; worker scans checkout_path or public/local clone_url with Gitleaks",
			RefTypes:         []string{"branch", "tag", "pull_request_head", "commit_sha"},
			SecretHandling:   "raw token and finding value stay outside events; only rule/file/line/redacted reference are recorded",
			OutboxMode:       "clone and scan are discovery.run outbox work, never inline request handling",
		},
		{
			ID:               "gitlab",
			Name:             "GitLab",
			RealtimeTriggers: []string{"push", "merge_request", "tag_push", "pipeline"},
			AuthMode:         "authenticated trstctl SecretsWrite webhook; GitLab token is referenced by credential_ref for private clone follow-up",
			IngestMode:       "POST normalized GitLab event enqueues a secret_repo discovery run; worker scans checkout_path or public/local clone_url with Gitleaks",
			RefTypes:         []string{"branch", "tag", "merge_request_source", "commit_sha"},
			SecretHandling:   "raw token and finding value stay outside events; only rule/file/line/redacted reference are recorded",
			OutboxMode:       "clone and scan are discovery.run outbox work, never inline request handling",
		},
		{
			ID:               "bitbucket",
			Name:             "Bitbucket",
			RealtimeTriggers: []string{"repo:push", "pullrequest:created", "pullrequest:updated", "repo:refs_changed"},
			AuthMode:         "authenticated trstctl SecretsWrite webhook; Bitbucket credential is referenced by credential_ref for private clone follow-up",
			IngestMode:       "POST normalized Bitbucket event enqueues a secret_repo discovery run; worker scans checkout_path or public/local clone_url with Gitleaks",
			RefTypes:         []string{"branch", "tag", "pull_request_source", "commit_sha"},
			SecretHandling:   "raw token and finding value stay outside events; only rule/file/line/redacted reference are recorded",
			OutboxMode:       "clone and scan are discovery.run outbox work, never inline request handling",
		},
	}
	return secretRepoScanPostureResponse{
		Capability:         "CAP-SCAN-01",
		Served:             true,
		GeneratedAt:        generatedAt,
		Providers:          providers,
		WebhookPaths:       []string{"/api/v1/secrets/scans/repositories/github/webhook", "/api/v1/secrets/scans/repositories/gitlab/webhook", "/api/v1/secrets/scans/repositories/bitbucket/webhook"},
		QueueModel:         "authenticated provider webhook records a tenant-scoped secret_repo discovery source/run and the discovery.run outbox worker performs clone/scan side effects",
		Scanner:            "gitleaks " + secretscan.GitleaksPinnedVersion,
		MinimumRulesActive: secretscan.GitleaksMinRulesActive,
		RedactionModel:     "scanner runs with redaction; parser drops secret/match fields and persists only rule, file, line, fingerprint, and credential_ref",
		EventFlow: []string{
			"discovery.source.upserted",
			"discovery.run.queued",
			"discovery.run.started",
			"discovery.finding.recorded",
			"discovery.run.completed",
		},
		ReleaseGates: []secretRepoScanGateResponse{
			{ID: "provider-webhook-contract", Command: "go test ./internal/api -run TestServedRepoSecretScanningCAPSCAN01", Artifact: "repo-secret-scan-contract", Required: true},
			{ID: "redaction-regression", Command: "go test ./internal/secretscan -run TestParseGitleaksDropsSecret", Artifact: "redaction transcript", Required: true},
			{ID: "architecture-lint", Command: "make lint test", Artifact: "local gate transcript", Required: true},
		},
		OperatorActions: []string{
			"install provider webhooks or CI callbacks for GitHub, GitLab, and Bitbucket repository events",
			"store provider credentials as tenant-scoped secret references, not inline webhook config",
			"send checkout_path or public/local clone_url to the normalized webhook; private credential_ref clone resolution is tracked as a shortfall",
			"route redacted leaked-secret findings into discovery, graph, risk, and incident workflows",
		},
		Residuals: []string{
			"provider webhook delivery latency and repository checkout time determine real-time detection delay",
			"native provider signature verification and private clone credential_ref resolution remain architecture follow-ups",
			"self-hosted Git providers may require custom CA/proxy configuration before clone workers can reach them",
			"historical full-repo scanning still depends on operators scheduling a baseline scan for existing repositories",
		},
		EvidenceRefs: []string{
			"internal/api/secrets.go",
			"internal/secretscan/gitleaks.go",
			"internal/orchestrator/discovery.go",
			"docs/features/secrets.md",
		},
		ArchitectureControls: []string{"AN-1", "AN-2", "AN-5", "AN-6", "AN-7", "AN-8"},
	}
}

func normalizeSecretRepoProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "github", "gitlab", "bitbucket":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func secretRepoScanConfig(provider string, req secretRepoScanWebhookRequest) (secretscan.RepositoryScanConfig, error) {
	repo := strings.TrimSpace(req.Repository)
	cloneURL := strings.TrimSpace(req.CloneURL)
	checkoutPath := strings.TrimSpace(req.CheckoutPath)
	if repo == "" {
		repo = repositoryNameFromTarget(cloneURL)
	}
	if repo == "" {
		repo = repositoryNameFromTarget(checkoutPath)
	}
	if repo == "" {
		return secretscan.RepositoryScanConfig{}, errStatus(http.StatusBadRequest, "repository is required")
	}
	if cloneURL == "" && checkoutPath == "" {
		return secretscan.RepositoryScanConfig{}, errStatus(http.StatusBadRequest, "clone_url or checkout_path is required")
	}
	if cloneURL != "" && strings.Contains(cloneURL, "://") {
		if strings.Contains(strings.SplitN(cloneURL, "://", 2)[1], "@") {
			return secretscan.RepositoryScanConfig{}, errStatus(http.StatusBadRequest, "clone_url must not embed credentials; use credential_ref")
		}
	}
	return secretscan.RepositoryScanConfig{
		Provider:      provider,
		Repository:    repo,
		CloneURL:      cloneURL,
		CheckoutPath:  checkoutPath,
		Ref:           strings.TrimSpace(req.Ref),
		CommitSHA:     strings.TrimSpace(req.CommitSHA),
		Event:         strings.TrimSpace(req.Event),
		CredentialRef: strings.TrimSpace(req.CredentialRef),
	}, nil
}

func repositoryNameFromTarget(target string) string {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	if target == "" {
		return ""
	}
	parts := strings.Split(target, "/")
	name := parts[len(parts)-1]
	return strings.TrimSuffix(name, ".git")
}

var secretRepoSourceNamespace = gouuid.MustParse("6eb35ad2-cbda-5a23-ae77-8e6ff69881f0")

func secretRepoSourceID(tenantID string, cfg secretscan.RepositoryScanConfig) string {
	key := strings.Join([]string{tenantID, cfg.Provider, cfg.Repository, cfg.Ref}, "\x00")
	return gouuid.NewSHA1(secretRepoSourceNamespace, []byte(key)).String()
}

func secretRepoSourceName(cfg secretscan.RepositoryScanConfig) string {
	name := "secret-repo:" + cfg.Provider + ":" + cfg.Repository
	if cfg.Ref != "" {
		name += ":" + cfg.Ref
	}
	return name
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
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
			sealed, err := seal.Seal(a.secrets.be.KEK, []byte(value), sealAAD(tenantID, name))
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
	plain, err := seal.Open(a.secrets.be.KEK, rec.Sealed, sealAAD(tenantID, name))
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

// ---- dynamic secret leases (dynsecret, F65) --------------------------------

// issueDynamicLease generates one scoped backend credential and opens a lease. The
// credential is returned only in this response (or an idempotent replay of it);
// later reads return metadata only.
//
//trstctl:mutation
func (a *API) issueDynamicLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req dynamicLeaseIssueRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.Provider == "" || req.Role == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "provider and role are required")
		}
		if req.TTLSeconds <= 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "ttl_seconds must be positive")
		}
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		lease, credential, err := engine.Issue(ctx, req.Provider, req.Role, time.Duration(req.TTLSeconds)*time.Second, idempotencyKey)
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		resp := toDynamicLeaseResponse(lease, credential)
		secret.Wipe(credential)
		return http.StatusCreated, resp, nil
	})
}

func (a *API) getDynamicLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	engine, err := a.secrets.dynamicLeaseEngine(tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	lease, err := engine.GetLease(r.PathValue("lease_id"))
	if err != nil {
		a.writeError(w, dynamicLeaseError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, toDynamicLeaseResponse(lease, nil))
}

//trstctl:mutation
func (a *API) renewDynamicLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	leaseID := r.PathValue("lease_id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req dynamicLeaseRenewRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.ExtendSeconds <= 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "extend_seconds must be positive")
		}
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		lease, err := engine.Renew(ctx, leaseID, time.Duration(req.ExtendSeconds)*time.Second)
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		return http.StatusOK, toDynamicLeaseResponse(lease, nil), nil
	})
}

//trstctl:mutation
func (a *API) revokeDynamicLease(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	leaseID := r.PathValue("lease_id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		if err := engine.Revoke(ctx, leaseID); err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		lease, err := engine.GetLease(leaseID)
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		_, _ = engine.RunRevocations(ctx)
		return http.StatusOK, toDynamicLeaseResponse(lease, nil), nil
	})
}

func toDynamicLeaseResponse(l dynsecret.Lease, credential []byte) dynamicLeaseResponse {
	return dynamicLeaseResponse{
		ID: l.ID, Provider: l.Provider, Role: l.Role, State: string(l.State),
		Credential: secretJSONBytes(credential), IssuedAt: l.IssuedAt, ExpiresAt: l.ExpiresAt,
	}
}

func dynamicLeaseError(err error) error {
	switch {
	case errors.Is(err, dynsecret.ErrUnknownProvider):
		return errStatus(http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, dynsecret.ErrLeaseNotFound):
		return errStatus(http.StatusNotFound, "no such dynamic secret lease")
	case errors.Is(err, dynsecret.ErrLeaseNotActive):
		return errStatus(http.StatusConflict, "dynamic secret lease is not active")
	default:
		return err
	}
}

func (s *secretsService) dynamicLeaseEngine(tenantID string) (*dynsecret.Engine, error) {
	if len(s.be.DynamicProviders) == 0 {
		return nil, errStatus(http.StatusServiceUnavailable, "dynamic secret lease providers are not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if engine, ok := s.leases[tenantID]; ok {
		return engine, nil
	}
	queue := dynsecret.RevokeQueue(dynsecret.NewMemoryQueue())
	if s.be.DynamicRevokeQueue != nil {
		queue = s.be.DynamicRevokeQueue(tenantID)
	}
	engine, err := dynsecret.New(dynsecret.Config{
		TenantID: tenantID, Providers: s.be.DynamicProviders, Queue: queue, Audit: s.be.Audit,
	})
	if err != nil {
		return nil, err
	}
	s.leases[tenantID] = engine
	return engine, nil
}

func (s *secretsService) dynamicLeaseEngines() []*dynsecret.Engine {
	s.mu.Lock()
	defer s.mu.Unlock()
	engines := make([]*dynsecret.Engine, 0, len(s.leases))
	for _, engine := range s.leases {
		engines = append(engines, engine)
	}
	return engines
}

func (s *secretsService) tickDynamicLeases(ctx context.Context) {
	for _, engine := range s.dynamicLeaseEngines() {
		worker := leaseworker.New(engine, s.be.DynamicLeaseWorkerInterval)
		_, _, _ = worker.Tick(ctx)
	}
}

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

func (r shareCreateResponse) wipeSecrets() { r.Token.wipe() }

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
		token := []byte(hex.EncodeToString(tokenRaw))
		tokenHash := crypto.SHA256Hex(token)
		shareRaw, err := crypto.RandomBytes(16)
		if err != nil {
			req.Value.wipe()
			return 0, nil, err
		}
		shareID := hex.EncodeToString(shareRaw)
		secret.Wipe(shareRaw)
		sealed, err := seal.Seal(a.secrets.be.KEK, []byte(req.Value), secretShareAAD(tenantID, shareID, tokenHash))
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

func (r shareRedeemResponse) wipeSecrets() { r.Value.wipe() }

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
		value, err := seal.Open(a.secrets.be.KEK, share.Sealed, secretShareAAD(tenantID, share.ShareID, share.TokenHash))
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

func (r pkiSecretResponse) wipeSecrets() {
	r.Certificate.wipe()
	r.PrivateKey.wipe()
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
	mgr, err := a.secrets.authManager(tenantID)
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
	a.writeJSON(w, http.StatusOK, machineLoginResponse{
		SessionID: sess.ID, Principal: sess.Principal, Method: sess.Method,
		Scopes: sess.Scopes, ExpiresAt: sess.ExpiresAt,
	})
}

var errMachineLoginNotConfigured = errors.New("machine login is not configured")

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
		plain, err := seal.Open(s.be.KEK, rec.Sealed, sealAAD(tenantID, path))
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

func (f fetcherFunc) Fetch(ctx context.Context, path string) ([]byte, time.Time, error) {
	return f(ctx, path)
}

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
func (s *secretsService) authManager(tenantID string) (*authmethod.Manager, error) {
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
