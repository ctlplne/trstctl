package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pkisecret"
	"trstctl.com/trstctl/internal/secretsdk"
	"trstctl.com/trstctl/internal/secretshare"
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
//   - secretshare (F60): a one-time self-destructing share — create returns a bearer
//     token out-of-band; redeem returns the secret exactly once (the GAP-001-fixed
//     View, which audits a non-secret share id + a SHA-256 of the token, never the
//     token itself). A second redeem fails.
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
	// is not configured. It is []byte and never logged (AN-8).
	AuthSecret []byte
	// SessionTTL bounds a machine-login session; zero selects one hour.
	SessionTTL time.Duration
}

// secretsService is the assembled served secrets surface. It owns the per-request
// construction of the five frameworks (each tenant-scoped, AN-1) and the in-process
// one-time-share links (per tenant, matching secretshare's in-memory design).
type secretsService struct {
	be SecretsBackend

	mu      sync.Mutex
	sharers map[string]*secretshare.Sharer // tenant -> its pending one-time shares
}

// WithSecrets mounts the served secrets/identity surface (GAP-006). The KEK, store,
// and audit sink are required; the issuing CA + auth secret are optional and gate
// their sub-features. When unset, the /api/v1/secrets/* routes fail closed with a
// clear "not enabled" problem.
func WithSecrets(be SecretsBackend) Option {
	return func(c *config) { c.secrets = &secretsService{be: be, sharers: map[string]*secretshare.Sharer{}} }
}

// SecretsServed reports whether the served secrets surface is wired (WithSecrets was
// given). It is the GAP-006 wiring assertion the acceptance test consults.
func (a *API) SecretsServed() bool { return a.secrets != nil }

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
		a.auditSecret(ctx, "secret.rotated", tenantID, rec.Name, rec.Version)
		return http.StatusOK, toSecretMeta(rec), nil
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

// ---- one-time secret share + redeem (secretshare, F60) ---------------------

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

// createShare mints a one-time share. The token is returned to the caller (the only
// copy delivered out-of-band). Idempotent (AN-5): a replay returns the same token (the
// original create result), so a retried create does not mint a second share.
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
		sharer := a.secrets.sharerFor(tenantID)
		token, err := sharer.Create(ctx, []byte(req.Value), ttl)
		req.Value.wipe() // the Sharer copied the bytes; wipe our transient plaintext (AN-8)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, shareCreateResponse{Token: secretJSONBytes(token), ExpiresAt: time.Now().Add(ttl)}, nil
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
// second redeem (or an expired/invalid token) fails — the single-use property the
// GAP-001 fix preserves. The single View call inside the closure enforces single-use:
// a fresh Idempotency-Key drives at most one View; a second redeem of the same token
// finds the link already consumed and fails.
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
		sharer, ok := a.secrets.existingSharer(tenantID)
		if !ok {
			return 0, nil, errStatus(http.StatusNotFound, "share not found or already consumed")
		}
		value, err := sharer.View(ctx, []byte(req.Token))
		if err != nil {
			return 0, nil, errStatus(http.StatusNotFound, "share not found or already consumed")
		}
		resp := shareRedeemResponse{Value: secretJSONBytes(value)}
		return http.StatusOK, resp, nil
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
	if len(a.secrets.be.AuthSecret) == 0 {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "machine login is not configured"))
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

// sharerFor returns the tenant's one-time-share Sharer, creating it on first use. The
// Sharer holds the still-pending links in memory (matching secretshare's design), so
// it must persist across requests within the tenant — hence the per-tenant map rather
// than a per-request instance. It is tenant-scoped (AN-1) and audits through the
// wired sink (the GAP-001 fix: a non-secret share id + SHA-256(token), never the
// token).
func (s *secretsService) sharerFor(tenantID string) *secretshare.Sharer {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.sharers[tenantID]
	if !ok {
		sh = secretshare.New(tenantID, s.be.Audit, time.Now)
		s.sharers[tenantID] = sh
	}
	return sh
}

// existingSharer returns the tenant's Sharer only if one exists (a redeem of a token
// for a tenant that never created a share cannot succeed). It does not create one.
func (s *secretsService) existingSharer(tenantID string) (*secretshare.Sharer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.sharers[tenantID]
	return sh, ok
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

// authManager builds a per-tenant authmethod.Manager with the token login method over
// the wired auth secret (F58). The method is tenant-scoped at construction so a
// session is bound to this tenant (AN-1).
func (s *secretsService) authManager(tenantID string) (*authmethod.Manager, error) {
	ttl := s.be.SessionTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return authmethod.New(authmethod.Config{
		TenantID: tenantID,
		Methods:  []authmethod.Method{authmethod.TokenMethod{Secret: s.be.AuthSecret, TenantID: tenantID}},
		Audit:    s.be.Audit,
		TTL:      ttl,
	})
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
