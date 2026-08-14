// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// cachedResponse is the response envelope stored by the idempotency recorder so
// a replayed key returns the identical status and body.
type cachedResponse struct {
	Status      int             `json:"s"`
	Body        json.RawMessage `json:"b"`
	Binding     string          `json:"h,omitempty"`
	ContentType string          `json:"c,omitempty"`
}

func cachedResponseContentType(body any) string {
	if _, ok := body.(*problem.Problem); ok {
		return problem.MediaType
	}
	return ""
}

func writeCachedResponseContentType(w http.ResponseWriter, contentType string) error {
	switch contentType {
	case "":
		w.Header().Set("Content-Type", "application/json")
	case problem.MediaType:
		w.Header().Set("Content-Type", problem.MediaType)
	default:
		return errors.New("api: cached response has unsupported content type")
	}
	return nil
}

type secretResponse interface {
	wipeSecrets()
}

// mutate runs a mutating operation under an idempotency key (AN-5): a replay
// returns the original response without re-executing. It requires a tenant and a
// non-empty key, both surfaced as problem+json.
func (a *API) mutate(w http.ResponseWriter, r *http.Request, idempotencyKey string, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	a.mutateWithRecorder(w, r, idempotencyKey, "", fn, false)
}

// mutateDurable wraps a mutation whose callback is itself an independently
// durable, idempotent state machine (normally event -> projection -> outbox). It
// preserves the identical HTTP response for replay, but unlike mutate it releases
// the tenant transaction before the callback waits for an external worker. This
// prevents a slow provider from consuming the API subsystem's PostgreSQL pool.
func (a *API) mutateDurable(w http.ResponseWriter, r *http.Request, idempotencyKey string, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	a.mutateWithRecorder(w, r, idempotencyKey, "", fn, true)
}

// mutateDurableBound is mutateDurable plus an immutable, non-secret digest of
// the authenticated principal and canonical request. The raw header value still
// reaches the AN-5 recorder; the binding prevents the same key from replaying a
// cached success for a different command or caller.
func (a *API) mutateDurableBound(w http.ResponseWriter, r *http.Request, idempotencyKey, binding string, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	a.mutateWithRecorder(w, r, idempotencyKey, binding, fn, true)
}

// mutatePreparedDurableBound is the scheduler-style durable path where the
// receiver's immutable work snapshot must be created in the exact transaction
// that first binds the outer key. The verifier compares the terminal receiver
// bytes before the outer protected result is committed.
func (a *API) mutatePreparedDurableBound(
	w http.ResponseWriter,
	r *http.Request,
	idempotencyKey, binding string,
	prepare func(context.Context, string, pgx.Tx) (orchestrator.PreparedDurableEffectClaim, error),
	verifyTerminal func(context.Context, string, pgx.Tx, []byte) error,
	fn func(context.Context, string) (int, any, error),
) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	if binding == "" || prepare == nil || verifyTerminal == nil || fn == nil {
		a.writeError(w, errors.New("api: prepared durable mutation is missing exact authority"))
		return
	}
	recordResult := func(ctx context.Context) ([]byte, error) {
		status, body, err := fn(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		bodyJSON := json.RawMessage("null")
		if body != nil {
			encoded, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			defer secret.Wipe(encoded)
			bodyJSON = encoded
		}
		return json.Marshal(cachedResponse{
			Status: status, Body: bodyJSON, Binding: binding,
			ContentType: cachedResponseContentType(body),
		})
	}
	raw, err := a.idem.DoPreparedDurableEffectBound(
		r.Context(), tenantID, idempotencyKey, binding,
		func(ctx context.Context, tx pgx.Tx) (orchestrator.PreparedDurableEffectClaim, error) {
			return prepare(ctx, tenantID, tx)
		},
		func(ctx context.Context, tx pgx.Tx, plaintext []byte) error {
			return verifyTerminal(ctx, tenantID, tx, plaintext)
		},
		recordResult,
	)
	if err != nil {
		if errors.Is(err, orchestrator.ErrIdempotencyConflict) || errors.Is(err, store.ErrIdempotencyConflict) {
			err = errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request")
		}
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(raw)
	var cached cachedResponse
	if err := json.Unmarshal(raw, &cached); err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(cached.Body)
	if !crypto.ConstantTimeEqual([]byte(cached.Binding), []byte(binding)) {
		a.writeError(w, errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request"))
		return
	}
	if cached.Status == http.StatusNoContent {
		w.WriteHeader(cached.Status)
		return
	}
	if err := writeCachedResponseContentType(w, cached.ContentType); err != nil {
		a.writeError(w, err)
		return
	}
	w.WriteHeader(cached.Status)
	_, _ = w.Write(cached.Body)
}

func (a *API) mutateWithRecorder(w http.ResponseWriter, r *http.Request, idempotencyKey, binding string, fn func(ctx context.Context, tenantID string) (int, any, error), durable bool) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	if binding == "" {
		principal, err := requestPrincipalSubject(r.Context())
		if err != nil {
			a.writeError(w, err)
			return
		}
		escapedPath := ""
		if r.URL != nil {
			escapedPath = r.URL.EscapedPath()
		}
		binding, err = mutationRouteBinding(principal, r.Method, escapedPath)
		if err != nil {
			a.writeError(w, err)
			return
		}
	}

	recordResult := func(ctx context.Context) ([]byte, error) {
		status, body, ferr := fn(ctx, tenantID)
		if ferr != nil {
			return nil, ferr
		}
		bodyJSON := json.RawMessage("null")
		if body != nil {
			if sr, ok := body.(secretResponse); ok {
				defer sr.wipeSecrets()
			}
			bj, mErr := json.Marshal(body)
			if mErr != nil {
				return nil, mErr
			}
			defer secret.Wipe(bj)
			bodyJSON = bj
		}
		return json.Marshal(cachedResponse{
			Status: status, Body: bodyJSON, Binding: binding,
			ContentType: cachedResponseContentType(body),
		})
	}
	var (
		raw []byte
		err error
	)
	if durable {
		raw, err = a.idem.DoDurableEffectBound(r.Context(), tenantID, idempotencyKey, binding, recordResult)
	} else {
		raw, err = a.idem.DoBound(r.Context(), tenantID, idempotencyKey, binding, recordResult)
	}
	if err != nil {
		if errors.Is(err, orchestrator.ErrIdempotencyConflict) {
			err = errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request")
		}
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(raw)

	var c cachedResponse
	if err := json.Unmarshal(raw, &c); err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(c.Body)
	if (c.Binding != "" || binding != "") && !crypto.ConstantTimeEqual([]byte(c.Binding), []byte(binding)) {
		a.writeError(w, errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request"))
		return
	}
	if c.Status == http.StatusNoContent {
		w.WriteHeader(c.Status)
		return
	}
	if err := writeCachedResponseContentType(w, c.ContentType); err != nil {
		a.writeError(w, err)
		return
	}
	w.WriteHeader(c.Status)
	_, _ = w.Write(c.Body)
}

// mutationRouteBinding scopes a raw Idempotency-Key to the authenticated caller
// and exact served route when a handler has no command-specific body binding.
// The domain label prevents this digest from being confused with any other
// binding scheme, and only the non-secret SHA-256 digest is persisted.
func mutationRouteBinding(principal, method, escapedPath string) (string, error) {
	material, err := json.Marshal(struct {
		Domain      string `json:"domain"`
		Principal   string `json:"principal"`
		Method      string `json:"method"`
		EscapedPath string `json:"escaped_path"`
	}{
		Domain:      "trstctl.api.mutation-route-binding.v1",
		Principal:   principal,
		Method:      method,
		EscapedPath: escapedPath,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
}
