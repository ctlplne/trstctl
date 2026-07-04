// SPDX-License-Identifier: MPL-2.0

package observ

import (
	"context"
	"encoding/json"
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

// Evaluate runs every probe and returns whether all passed plus a per-dependency
// result ("ok" or the error text). Each probe runs under a child span of ctx.
func (r *Readiness) Evaluate(ctx context.Context) (bool, map[string]string) {
	allOK := true
	results := make(map[string]string, len(r.checks))
	for _, c := range r.checks {
		cctx, span := r.tracer.Start(ctx, "readiness."+c.Name)
		err := c.Probe(cctx)
		if err != nil {
			allOK = false
			results[c.Name] = err.Error()
			span.SetAttr("status", "error")
		} else {
			results[c.Name] = "ok"
			span.SetAttr("status", "ok")
		}
		span.End()
	}
	return allOK, results
}

// Handler serves GET /readyz: 200 with per-dependency status when ready, 503 when
// any dependency is down (so a Kubernetes readiness probe removes the pod from
// rotation, and an operator sees which dependency hurts).
func (r *Readiness) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ok, results := r.Evaluate(req.Context())
		status := http.StatusOK
		overall := "ok"
		if !ok {
			status = http.StatusServiceUnavailable
			overall = "degraded"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": overall, "checks": results})
	}
}
