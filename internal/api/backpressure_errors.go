// SPDX-License-Identifier: MPL-2.0

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
	case store.IsTransactionRollback(err):
		// PostgreSQL rolled the command's transaction back because of a concurrent
		// transaction (serialization failure or deadlock, e.g. the inline apply
		// racing the durable tail on the same rows). Nothing committed and the
		// idempotency claim was released, so the same request retries safely.
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "the request's transaction was rolled back by a concurrent transaction; nothing was committed — retry with the same Idempotency-Key"))
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
