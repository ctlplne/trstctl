// SPDX-License-Identifier: MPL-2.0

package api

// Served BYOK/HSM managed-key lifecycle (CRYPTO-005 / EXC-CRYPTO-01). The
// crypto.RemoteKeyLifecycle primitives (generate/rotate/revoke/zeroize for a key
// whose private material lives in a KMS/HSM and never enters this process) were
// previously library-tier — implemented and tested but reachable from no served
// route. These handlers expose them on the running control plane: each is
// tenant-scoped (AN-1), idempotent (AN-5) through a.mutate, event-sourced (AN-2) via
// the managedkeys.Service's injected sink, and — for the destructive transitions —
// gated by the same distinct-approver dual control the served issuance gate uses.
// The private key is never in a request or response; for a remote key it is never
// in this address space at all.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// ManagedKey is the key-material-free result contract returned by the licensed
// managed-key implementation. Core API owns this DTO so the route handlers do not
// link the EE service package.
type ManagedKey struct {
	KeyID       string           `json:"key_id"`
	Algorithm   crypto.Algorithm `json:"algorithm"`
	Version     int              `json:"version"`
	State       string           `json:"state"`
	PublicDER   []byte           `json:"public_der,omitempty"`
	Extractable bool             `json:"extractable"`
}

var (
	ErrManagedKeyNotApproved = errors.New("managedkeys: dual-control approval required")
	ErrManagedKeyUnknown     = errors.New("managedkeys: unknown key for tenant")
	ErrManagedKeyRefRequired = errors.New("managedkeys: key ref (id) is required")
)

// ManagedKeyService is the served managed-key lifecycle the API drives.
// The API depends only on this minimal interface
// so it never links a concrete KMS backend; the composition root wires the backend,
// event sink, dual-control gate, and optional service-level idempotency into the
// service. The served HTTP path binds every handler's canonical command and
// authenticated principal before invoking the durable service (AN-5). The same raw
// Idempotency-Key reaches both layers so the API owns byte-for-byte HTTP replay and
// the durable receiver owns collapse of the event/outbox effect.
type ManagedKeyService interface {
	Generate(ctx context.Context, tenantID string, alg crypto.Algorithm, idempotencyKey, requestBinding string) (ManagedKey, error)
	Rotate(ctx context.Context, tenantID, keyID, requester, idempotencyKey, requestBinding string) (ManagedKey, error)
	Revoke(ctx context.Context, tenantID, keyID, requester, idempotencyKey, requestBinding string) (ManagedKey, error)
	Zeroize(ctx context.Context, tenantID, keyID, requester, idempotencyKey, requestBinding string) (ManagedKey, error)
}

// WithManagedKeys mounts the served managed-key lifecycle surface (CRYPTO-005). When
// unset, the /api/v1/managed-keys/* routes fail closed with a clear "not enabled"
// problem (the capability requires a configured KMS/HSM custody backend).
func WithManagedKeys(svc ManagedKeyService) Option {
	return func(c *config) { c.managedKeys = svc }
}

// ManagedKeysServed reports whether the served managed-key surface is wired
// (WithManagedKeys was given). It is the CRYPTO-005 wiring assertion the acceptance
// test consults.
func (a *API) ManagedKeysServed() bool { return a.managedKeys != nil }

func managedKeysDisabledProblem() *apiError {
	return errStatus(http.StatusNotImplemented,
		"managed-key lifecycle is not enabled (configure a KMS/HSM custody backend)")
}

// ---- request/response shapes (key-material-free) ---------------------------

type managedKeyGenerateRequest struct {
	Algorithm string `json:"algorithm"`
}

type managedKeyActionRequest struct {
	KeyID string `json:"key_id"`
}

type managedKeyApprovalRequest struct {
	KeyID        string `json:"key_id"`
	Action       string `json:"action"`
	RequestID    string `json:"request_id"`
	IntentDigest string `json:"intent_digest"`
}

type managedKeyApprovalResponse struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Approver  string `json:"approver"`
	Approvals int    `json:"approvals"`
}

// Managed-key action constants are the canonical approval/service vocabulary.
// The core recorder and licensed lifecycle both compile against these values, so
// an approval can never drift onto a lookalike action string.
const (
	ManagedKeyActionGenerate = "managedkey:generate"
	ManagedKeyActionRotate   = "managedkey:rotate"
	ManagedKeyActionRevoke   = "managedkey:revoke"
	ManagedKeyActionZeroize  = "managedkey:zeroize"
)

var managedKeyApprovalActions = []string{"rotate", "revoke", "zeroize"}

var managedKeyCanonicalApprovalActions = []string{
	ManagedKeyActionRotate,
	ManagedKeyActionRevoke,
	ManagedKeyActionZeroize,
}

// managedKeyResponse is the public view of a managed key: identity, algorithm,
// version, state, and PKIX public key — never the private material.
type managedKeyResponse struct {
	KeyID       string `json:"key_id"`
	Algorithm   string `json:"algorithm"`
	Version     int    `json:"version"`
	State       string `json:"state"`
	PublicDER   []byte `json:"public_der,omitempty"`
	Extractable bool   `json:"extractable"`
}

func toManagedKeyResponse(r ManagedKey) managedKeyResponse {
	return managedKeyResponse{
		KeyID:       r.KeyID,
		Algorithm:   string(r.Algorithm),
		Version:     r.Version,
		State:       string(r.State),
		PublicDER:   r.PublicDER,
		Extractable: r.Extractable,
	}
}

// requesterFor returns the authenticated principal's subject, which the dual-control
// gate treats as the requester (and therefore never counts as its own approver).
func requesterFor(ctx context.Context) (string, error) {
	p, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if p.Subject == "" {
		return "", errStatus(http.StatusUnauthorized, "an authenticated principal is required")
	}
	return p.Subject, nil
}

// mapManagedKeyError maps service-layer errors to problem+json statuses.
func mapManagedKeyError(err error) error {
	switch {
	case errors.Is(err, orchestrator.ErrIdempotencyConflict):
		return errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request")
	case errors.Is(err, ErrManagedKeyNotApproved):
		return errStatus(http.StatusForbidden, "dual control: "+err.Error())
	case errors.Is(err, ErrManagedKeyUnknown):
		return errStatus(http.StatusNotFound, "no such managed key for this tenant")
	case errors.Is(err, ErrManagedKeyRefRequired):
		return errStatus(http.StatusBadRequest, "key_id is required")
	default:
		return err
	}
}

// ---- handlers --------------------------------------------------------------

// generateManagedKey mints a new managed key in the configured KMS/HSM. The private
// material is born in the provider and never enters this process. Idempotent (AN-5),
// event-sourced (AN-2). Generation creates new material, so it needs no prior
// approval.
//
//trstctl:mutation
func (a *API) generateManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req managedKeyGenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.Algorithm == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "algorithm is required"))
		return
	}
	alg, err := parseManagedKeyAlgorithm(req.Algorithm)
	if err != nil {
		a.writeError(w, err)
		return
	}
	requester, err := requesterFor(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := managedKeyRequestBinding("generate", requester, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		res, err := a.managedKeys.Generate(ctx, tenantID, alg, idempotencyKey, binding)
		if err != nil {
			return 0, nil, mapManagedKeyError(err)
		}
		return http.StatusCreated, toManagedKeyResponse(res), nil
	})
}

// rotateManagedKey mints a successor for an existing managed key (supersede-then-
// retire). Destructive of the current generation's authority, so it requires a
// distinct-approver approval (dual control) enforced by the service.
//
//trstctl:mutation
func (a *API) rotateManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.managedKeyAction(w, r, idempotencyKey, "rotate", a.managedKeys.Rotate)
}

// revokeManagedKey disables a managed key at the provider (it refuses further
// signatures). Requires a distinct-approver approval (dual control).
//
//trstctl:mutation
func (a *API) revokeManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.managedKeyAction(w, r, idempotencyKey, "revoke", a.managedKeys.Revoke)
}

// zeroizeManagedKey schedules destruction of a managed key's material at the
// provider (irreversible after the provider window). Requires a distinct-approver
// approval (dual control).
//
//trstctl:mutation
func (a *API) zeroizeManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.managedKeyAction(w, r, idempotencyKey, "zeroize", a.managedKeys.Zeroize)
}

// approveManagedKeyAction records one distinct principal's approval for an exact
// opaque provider key handle and destructive action. The key id stays in JSON: HSM
// and cloud-KMS handles routinely contain slashes and must never be reinterpreted
// as URL path segments. Only this closed-set translation can produce the canonical
// managedkey:* action strings consulted by the licensed lifecycle service.
//
//trstctl:mutation
func (a *API) approveManagedKeyAction(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	if a.approvals == nil {
		a.writeError(w, errStatus(http.StatusNotImplemented, "managed-key dual-control approval is not enabled on this deployment"))
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req managedKeyApprovalRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.KeyID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "key_id is required"))
		return
	}
	canonicalAction, ok := canonicalManagedKeyApprovalAction(req.Action)
	if !ok {
		a.writeError(w, errStatus(http.StatusBadRequest, `action must be "rotate", "revoke", or "zeroize"`))
		return
	}
	approver, err := requesterFor(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	command := ApprovalDecisionCommand{
		RequestID: strings.TrimSpace(req.RequestID), IntentDigest: strings.TrimSpace(req.IntentDigest),
		Approver: approver, Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: "managed_key", ExpectedResourceID: req.KeyID,
		ExpectedAction: canonicalAction,
	}
	if _, err := a.preflightApprovalDecision(r, command); err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := managedKeyRequestBinding("approve:"+canonicalAction, approver, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateWithRecorder(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		record, recordErr := a.approvals.RecordApproval(ctx, tenantID, command)
		if recordErr != nil {
			return 0, nil, approvalAPIError(recordErr)
		}
		return http.StatusOK, managedKeyApprovalResponse{
			Resource: req.KeyID, Action: canonicalAction, Approver: approver, Approvals: record.ApprovalCount,
		}, nil
	}, false)
}

func canonicalManagedKeyApprovalAction(action string) (string, bool) {
	switch action {
	case "rotate":
		return ManagedKeyActionRotate, true
	case "revoke":
		return ManagedKeyActionRevoke, true
	case "zeroize":
		return ManagedKeyActionZeroize, true
	default:
		return "", false
	}
}

// managedKeyAction is the shared body of the destructive handlers. It decodes and
// validates the command and authenticated requester before the recorder can return
// a cached response, then binds both to the raw tenant-global idempotency key. A
// changed key, action, or caller therefore receives 409 without reaching approval
// or the durable service.
func (a *API) managedKeyAction(w http.ResponseWriter, r *http.Request, idempotencyKey, operation string, op func(ctx context.Context, tenantID, keyID, requester, idem, requestBinding string) (ManagedKey, error)) {
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req managedKeyActionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.KeyID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "key_id is required"))
		return
	}
	requester, err := requesterFor(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := managedKeyRequestBinding(operation, requester, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		res, err := op(ctx, tenantID, req.KeyID, requester, idempotencyKey, binding)
		if err != nil {
			return 0, nil, mapManagedKeyError(err)
		}
		return http.StatusOK, toManagedKeyResponse(res), nil
	})
}

func parseManagedKeyAlgorithm(raw string) (crypto.Algorithm, error) {
	alg := crypto.Algorithm(raw)
	switch alg {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096,
		crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521:
		return alg, nil
	default:
		return "", errStatus(http.StatusBadRequest, "unsupported managed-key algorithm")
	}
}

func managedKeyRequestBinding(operation, principal string, request any) (string, error) {
	encoded, err := json.Marshal(struct {
		Domain    string `json:"domain"`
		Operation string `json:"operation"`
		Principal string `json:"principal"`
		Request   any    `json:"request"`
	}{Domain: "trstctl.api.managed-key-binding.v1", Operation: operation, Principal: principal, Request: request})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}
