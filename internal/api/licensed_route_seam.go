// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"
)

// DecodeJSON is the licensed-route wrapper for the core request decoder.
func DecodeJSON(r *http.Request, v any) error { return decodeJSON(r, v) }

// DecodeJSONStrict applies the same size and trailing-token limits as DecodeJSON
// and also rejects fields outside the exact wire struct. Use it for destructive
// commands where silently ignoring a caller-asserted control could be unsafe.
func DecodeJSONStrict(r *http.Request, v any) error {
	return decodeJSONWithLimitOptions(r, v, defaultRESTJSONBodyLimit, true)
}

// AuthenticatedPrincipalSubject returns the exact authenticated subject already
// placed in the request context by the shared authorization middleware. Licensed
// handlers use this instead of accepting caller-asserted operator identities.
func AuthenticatedPrincipalSubject(ctx context.Context) (string, error) {
	return requestPrincipalSubject(ctx)
}

// ErrStatus lets licensed route handlers return core problem+json errors without
// depending on unexported error types.
func ErrStatus(status int, detail string) error { return errStatus(status, detail) }

// ErrWithStatus wraps an arbitrary decode/domain error with an HTTP status for
// the shared problem+json writer.
func ErrWithStatus(status int, err error) error { return errWithStatus(status, err) }

// Mutate runs a licensed mutating handler through the same idempotency path as
// core routes.
func (a *API) Mutate(w http.ResponseWriter, r *http.Request, idempotencyKey string, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	a.mutate(w, r, idempotencyKey, fn)
}

// ObserveFeature emits the shared per-feature telemetry signal for licensed
// route handlers.
func (a *API) ObserveFeature(feature, action string, start time.Time, err error) {
	a.observeFeature(feature, action, start, err)
}

// Tenant resolves the authenticated caller's tenant for a licensed READ handler,
// the same way Mutate resolves it for a licensed write. It is the feature-neutral
// read seam: a licensed GET handler (which does not go through Mutate) uses it to
// scope its query to the caller's tenant without the core importing ee/. It
// returns false when no valid tenant is present (the handler should then refuse).
func (a *API) Tenant(r *http.Request) (string, bool) { return a.tenant(r) }

// WriteJSON, WriteError, and WriteProblemUnauthorized complete the licensed
// READ seam that Tenant opened: a licensed GET handler does not go through
// Mutate, so without these it could not render a response without the MPL
// core exporting its problem+json machinery. They are thin pass-throughs, so
// a licensed route's error shape is identical to a core route's.
func (a *API) WriteJSON(w http.ResponseWriter, status int, v any) { a.writeJSON(w, status, v) }

func (a *API) WriteError(w http.ResponseWriter, err error) { a.writeError(w, err) }

func (a *API) WriteProblemUnauthorized(w http.ResponseWriter) {
	a.writeProblem(w, problemUnauthorized())
}
