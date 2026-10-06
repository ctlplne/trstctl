// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// writeBackpressureError renders the answers of the idempotency contract under
// concurrency and the deadline expiry under datastore pressure, so none of them
// surfaces as a misleading 500 (DP2-049, DP2-050, DP2-052). It reports whether it
// handled err, in the shape writeError's switch uses for every error family.
func (a *API) writeBackpressureError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, orchestrator.ErrInProgress):
		// An identical request with this Idempotency-Key is still executing; the
		// recorded result is not there yet. A retry will replay it (AN-5).
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, problem.New(http.StatusConflict, "an identical request with this Idempotency-Key is still in progress; retry shortly to receive its result"))
	case errors.Is(err, orchestrator.ErrEffectIndeterminate):
		a.writeProblem(w, problem.New(http.StatusConflict, "the original request's effect is indeterminate: inspect the resource before retrying with a new Idempotency-Key"))
	case errors.Is(err, store.ErrCertificateRecordingRebuildRequired):
		// Repeating issuance cannot repair unknown history ordering. Keep the
		// original command identity and require operator recovery before retry.
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "certificate history requires an ordered read-model rebuild; ask the operator to stop mutating control-plane replicas and run trstctl --rebuild with the existing deployment configuration, then retry with the same Idempotency-Key").
			WithExtension("recovery_required", "read_model_rebuild").WithExtension("retryable", false))
	case store.IsTransactionRollback(err):
		// This proves only one PostgreSQL transaction was rolled back. A command
		// may already have committed an event or another durable step outside
		// that transaction. Never advertise an automatic retry of the whole
		// command from this generic handler; event-aware owners reconcile and
		// return their exact result or ErrEffectIndeterminate instead.
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "A PostgreSQL transaction was rolled back after a concurrent write. Inspect the resource and audit before retrying this command with the same Idempotency-Key.").
			WithExtension("retryable", false).WithExtension("sqlstate", store.SQLState(err)))
	case errors.Is(err, context.DeadlineExceeded):
		// The request ran into its deadline while the datastore was saturated:
		// the same retryable 503 as the pool-acquire timeout, not a 500.
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "the request was bounded by its deadline while the datastore was busy — retry"))
	default:
		return false
	}
	return true
}
