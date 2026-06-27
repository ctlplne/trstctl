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
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
)

// ManagedKey is the key-material-free result contract returned by the licensed
// managed-key implementation. Core API owns this DTO so the route handlers do not
// link the EE service package.
type ManagedKey struct {
	KeyID     string           `json:"key_id"`
	Algorithm crypto.Algorithm `json:"algorithm"`
	Version   int              `json:"version"`
	State     string           `json:"state"`
	PublicDER []byte           `json:"public_der,omitempty"`
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
// service. The served HTTP path already wraps every handler in a.mutate (AN-5), so
// these handlers pass an empty service idempotency key and let the API idempotency
// recorder own request replay exactly once.
type ManagedKeyService interface {
	Generate(ctx context.Context, tenantID string, alg crypto.Algorithm, idempotencyKey string) (ManagedKey, error)
	Rotate(ctx context.Context, tenantID, keyID, requester, idempotencyKey string) (ManagedKey, error)
	Revoke(ctx context.Context, tenantID, keyID, requester, idempotencyKey string) (ManagedKey, error)
	Zeroize(ctx context.Context, tenantID, keyID, requester, idempotencyKey string) (ManagedKey, error)
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

// managedKeyResponse is the public view of a managed key: identity, algorithm,
// version, state, and PKIX public key — never the private material.
type managedKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Version   int    `json:"version"`
	State     string `json:"state"`
	PublicDER []byte `json:"public_der,omitempty"`
}

func toManagedKeyResponse(r ManagedKey) managedKeyResponse {
	return managedKeyResponse{
		KeyID:     r.KeyID,
		Algorithm: string(r.Algorithm),
		Version:   r.Version,
		State:     string(r.State),
		PublicDER: r.PublicDER,
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req managedKeyGenerateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.Algorithm == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "algorithm is required")
		}
		res, err := a.managedKeys.Generate(ctx, tenantID, crypto.Algorithm(req.Algorithm), "")
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		return managedKeyMutation(ctx, r, tenantID, a.managedKeys.Rotate)
	})
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		return managedKeyMutation(ctx, r, tenantID, a.managedKeys.Revoke)
	})
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		return managedKeyMutation(ctx, r, tenantID, a.managedKeys.Zeroize)
	})
}

// managedKeyMutation is the shared closure body of the three destructive handlers:
// it decodes the key id, resolves the requester, and invokes the service op (which
// enforces dual control before any provider side effect). Request idempotency is
// already handled by a.mutate at the HTTP boundary, so the service receives an empty
// idempotency key and does not open a nested recorder transaction.
func managedKeyMutation(ctx context.Context, r *http.Request, tenantID string, op func(ctx context.Context, tenantID, keyID, requester, idem string) (ManagedKey, error)) (int, any, error) {
	var req managedKeyActionRequest
	if err := decodeJSON(r, &req); err != nil {
		return 0, nil, errWithStatus(http.StatusBadRequest, err)
	}
	if req.KeyID == "" {
		return 0, nil, errStatus(http.StatusBadRequest, "key_id is required")
	}
	requester, err := requesterFor(ctx)
	if err != nil {
		return 0, nil, err
	}
	res, err := op(ctx, tenantID, req.KeyID, requester, "")
	if err != nil {
		return 0, nil, mapManagedKeyError(err)
	}
	return http.StatusOK, toManagedKeyResponse(res), nil
}
