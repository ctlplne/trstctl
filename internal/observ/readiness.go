// SPDX-License-Identifier: MPL-2.0

package observ

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// Check is a named readiness probe for one dependency (DB, NATS, signer, …).
type Check struct {
	Name  string
	Probe func(ctx context.Context) error
}

// Readiness aggregates dependency probes into a /readyz endpoint. Each probe runs
// under a child span of the request, so a readiness call produces a trace that
// spans the real subsystems.
type Readiness struct {
	tracer *Tracer
	checks []Check
}

// NewReadiness builds a readiness aggregator over the given checks.
func NewReadiness(tracer *Tracer, checks ...Check) *Readiness {
	if tracer == nil {
		tracer = NewTracer(nil)
	}
	return &Readiness{tracer: tracer, checks: checks}
}

// DegradedError is a probe outcome between ok and failed: the dependency is
// reachable but the probe was shed by load (a saturated request pool, an
// exhausted probe budget). Readiness stays 200 so a load balancer keeps the
// replica in rotation, and the check text and the "degraded" list say why, so
// an operator can alert on a replica that is shedding for longer than a burst.
type DegradedError struct{ Reason string }

func (e DegradedError) Error() string { return "degraded: " + e.Reason }

// Degraded builds the shed-by-load probe outcome.
func Degraded(reason string) error { return DegradedError{Reason: reason} }

// Evaluate runs every probe and returns whether all passed plus a per-dependency
// result ("ok", "degraded: …" or the error text). A degraded probe does not fail
// readiness. Each probe runs under a child span of ctx.
func (r *Readiness) Evaluate(ctx context.Context) (bool, map[string]string) {
	ok, results, _ := r.EvaluateDetailed(ctx)
	return ok, results
}

// EvaluateDetailed is Evaluate plus the names of the probes that answered
// degraded, in check order.
func (r *Readiness) EvaluateDetailed(ctx context.Context) (bool, map[string]string, []string) {
	allOK := true
	results := make(map[string]string, len(r.checks))
	var degraded []string
	for _, c := range r.checks {
		cctx, span := r.tracer.Start(ctx, "readiness."+c.Name)
		err := c.Probe(cctx)
		var shed DegradedError
		switch {
		case err == nil:
			results[c.Name] = "ok"
			span.SetAttr("status", "ok")
		case errors.As(err, &shed):
			results[c.Name] = shed.Error()
			degraded = append(degraded, c.Name)
			span.SetAttr("status", "degraded")
		default:
			allOK = false
			results[c.Name] = err.Error()
			span.SetAttr("status", "error")
		}
		span.End()
	}
	return allOK, results, degraded
}

// Handler serves GET /readyz: 200 with per-dependency status when ready, 503 when
// any dependency is down (so a Kubernetes readiness probe removes the pod from
// rotation, and an operator sees which dependency hurts).
func (r *Readiness) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ok, results, degraded := r.EvaluateDetailed(req.Context())
		status := http.StatusOK
		overall := "ok"
		if !ok {
			status = http.StatusServiceUnavailable
			overall = "degraded"
		}
		body := map[string]any{"status": overall, "checks": results}
		if len(degraded) > 0 {
			// Ready, but these probes were shed by load: 200 keeps the replica in
			// rotation while the list makes the shedding visible and alertable.
			body["degraded"] = degraded
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}
