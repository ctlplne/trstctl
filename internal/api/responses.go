// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// writeError maps an error to a problem+json response.
func (a *API) writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	switch {
	case errors.Is(err, context.Canceled):
		// The caller went away while a bounded datastore read was running (for
		// example, a browser navigated to another workspace). That is not a
		// server failure. Use the established 499 code so access logs and SLOs do
		// not turn a harmless client cancellation into a misleading 500.
		a.writeProblem(w, problem.New(499, "request canceled by client").WithTitle("Client Closed Request"))
	case errors.As(err, &ae):
		p := problem.New(ae.status, ae.detail)
		for k, v := range ae.ext {
			p = p.WithExtension(k, v)
		}
		a.writeProblem(w, p)
	case a.writeExternalCAError(w, err):
	case a.writeCAHierarchyError(w, err):
	case a.writeEdgeDelegationError(w, err):
	case a.writeAttestedIssuanceError(w, err):
	case a.writeBrokerError(w, err):
	case a.writeEphemeralError(w, err):
	case a.writePAMError(w, err):
	case a.writeSSHWorkflowError(w, err):
	case writeTenantCryptoError(a, w, err):
	case a.writeBackpressureError(w, err):
	case store.IsBusy(err):
		w.Header().Set("Retry-After", "1")
		// Bounded-latency datastore failure (pool saturation or server-side
		// statement deadline): a structured 503 tells the caller to retry
		// rather than hanging or mislabeling it a 500 (OPS-TIMEOUTS-001).
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "datastore is busy; the request was bounded by its acquire/statement deadline — retry"))
	case store.IsNotFound(err):
		a.writeProblem(w, problem.New(http.StatusNotFound, "resource not found"))
	case errors.Is(err, orchestrator.ErrRenewalWorkPending):
		a.writeProblem(w, problem.New(http.StatusConflict, err.Error()))
	case errors.Is(err, orchestrator.ErrInvalidTransition):
		p := problem.New(http.StatusConflict, err.Error())
		var te *orchestrator.TransitionError
		if errors.As(err, &te) {
			p = p.WithExtension("from", string(te.From)).WithExtension("to", string(te.To))
		}
		a.writeProblem(w, p)
	default:
		a.logInternalError(w, err) // the client sees "internal error"; the operator sees why, redacted (DP2-059)
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "internal error"))
	}
}

func writeTenantCryptoError(a *API, w http.ResponseWriter, err error) bool {
	status, ok := tenantseal.StatusOf(err)
	if !ok {
		return false
	}
	a.writeProblem(w, problem.New(http.StatusLocked, "tenant cryptographic access is unavailable").
		WithExtension("tenant_key_domain_status", string(status)))
	return true
}

func (a *API) writeProblem(w http.ResponseWriter, p *problem.Problem) {
	if localizeProblemResponse(w, p) {
		w.Header().Set("Content-Language", problemLocaleFromWriter(w))
		addVaryHeader(w.Header(), "Accept-Language")
	}
	_ = p.Write(w)
}

func problemUnauthorized() *problem.Problem {
	return problem.New(http.StatusUnauthorized, "missing or invalid tenant")
}

func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "failed to encode response"))
		return
	}
	defer secret.Wipe(b)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (a *API) notFound(w http.ResponseWriter, _ *http.Request) {
	a.writeProblem(w, problem.New(http.StatusNotFound, "no such resource"))
}

func errWithStatus(status int, err error) *apiError {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	return errStatus(status, err.Error())
}
