package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pkisecret"
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
