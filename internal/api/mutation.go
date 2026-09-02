// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
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

// mutatePublicTenantBound applies AN-5 to a deliberately public credential
// exchange after the handler has resolved its tenant lookup hint. The synthetic
// principal carries only that already-resolved tenant into the common recorder;
// it is not authentication or authorization, and a mandatory caller-supplied
// binding prevents the recorder from deriving authority from it.
func (a *API) mutatePublicTenantBound(w http.ResponseWriter, r *http.Request, tenantID, idempotencyKey, binding string, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	if tenantID == "" || binding == "" {
		a.writeError(w, errors.New("api: public mutation is missing exact tenant or request binding"))
		return
	}
	ctx := context.WithValue(r.Context(), principalCtxKey, authz.Principal{
		TenantID: tenantID,
		Subject:  "public-credential-exchange",
	})
	a.mutateWithRecorder(w, r.WithContext(ctx), idempotencyKey, binding, fn, false)
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
		var body []byte
		binding, body, err = mutationRequestBinding(r, principal)
		defer secret.Wipe(body)
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

// mutationRequestBinding scopes a raw Idempotency-Key to the authenticated
// caller and exact served request when a handler has no command-specific
// binding. The bounded request body is restored before the callback sees it and
// wiped when the mutation returns. Only its SHA-256 digest enters the binding.
func mutationRequestBinding(r *http.Request, principal string) (binding string, body []byte, err error) {
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, defaultRESTJSONBodyLimit+1))
		_ = r.Body.Close()
		if err != nil {
			secret.Wipe(body)
			return "", nil, errStatus(http.StatusBadRequest, "failed to read mutation request body")
		}
		if len(body) > defaultRESTJSONBodyLimit {
			secret.Wipe(body)
			return "", nil, errStatus(http.StatusRequestEntityTooLarge, "mutation request body too large")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	escapedPath, query := "", ""
	if r.URL != nil {
		escapedPath = r.URL.EscapedPath()
		query = r.URL.Query().Encode()
	}
	if len(body) == 0 && query == "" {
		// Preserve the durable v1 binding for truly bodyless/queryless commands:
		// their complete semantics already fit in principal+method+path.
		binding, err = mutationRouteBinding(principal, r.Method, escapedPath)
	} else {
		binding, err = mutationRequestRouteBinding(principal, r.Method, escapedPath, query, crypto.SHA256Hex(body))
	}
	if err != nil {
		secret.Wipe(body)
		return "", nil, err
	}
	return binding, body, nil
}

// mutationRouteBinding is the durable v1 binding for a request with no body and
// no query. Keeping it stable preserves safe replays across upgrades.
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

// mutationRequestRouteBinding hashes non-secret command coordinates and the
// bounded body digest. The v2 domain prevents it from being confused with the
// historical route-only binding or any subsystem-specific binding.
func mutationRequestRouteBinding(principal, method, escapedPath, query, bodyDigest string) (string, error) {
	material, err := json.Marshal(struct {
		Domain      string `json:"domain"`
		Principal   string `json:"principal"`
		Method      string `json:"method"`
		EscapedPath string `json:"escaped_path"`
		Query       string `json:"query"`
		BodyDigest  string `json:"body_digest"`
	}{
		Domain:      "trstctl.api.mutation-request-binding.v2",
		Principal:   principal,
		Method:      method,
		EscapedPath: escapedPath,
		Query:       query,
		BodyDigest:  bodyDigest,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
}
