// SPDX-License-Identifier: BUSL-1.1

package observ

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Check is a named readiness probe for one dependency (DB, NATS, signer, …).
type Check struct {
	Name  string
	Probe func(ctx context.Context) error
}

// Readiness aggregates dependency probes into a /readyz endpoint. Each actual
// evaluation runs child spans; public requests briefly share one result.
type Readiness struct {
	tracer *Tracer
	checks []Check

	publicMu       sync.Mutex
	publicPending  chan struct{}
	publicResult   *publicReadinessResult
	publicValidTil time.Time
}

type publicReadinessResult struct {
	ready    bool
	checks   map[string]string
	degraded []string
}

const publicReadinessCacheTTL = time.Second
const publicReadinessProbeBudget = 10 * time.Second

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
// replica in rotation. The public check and degraded list show which probe was
// shed; authenticated diagnostics retain its reason.
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

// publicEvaluation bounds probe work across concurrent public requests. The
// authenticated operations view still evaluates fresh and keeps probe detail.
func (r *Readiness) publicEvaluation(requestCtx context.Context) (publicReadinessResult, bool) {
	for {
		r.publicMu.Lock()
		if r.publicResult != nil && time.Now().Before(r.publicValidTil) {
			result := *r.publicResult
			r.publicMu.Unlock()
			return result, true
		}
		if pending := r.publicPending; pending != nil {
			r.publicMu.Unlock()
			select {
			case <-pending:
				continue
			case <-requestCtx.Done():
				return publicReadinessResult{}, false
			}
		}
		pending := make(chan struct{})
		r.publicPending = pending
		r.publicMu.Unlock()
		return r.runPublicEvaluation(requestCtx, pending), true
	}
}

func (r *Readiness) runPublicEvaluation(requestCtx context.Context, pending chan struct{}) publicReadinessResult {
	defer func() {
		r.publicMu.Lock()
		r.publicPending = nil
		close(pending)
		r.publicMu.Unlock()
	}()
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(requestCtx), publicReadinessProbeBudget)
	defer cancel()
	ready, detailed, degraded := r.EvaluateDetailed(probeCtx)
	degradedNames := make(map[string]bool, len(degraded))
	for _, name := range degraded {
		degradedNames[name] = true
	}
	checks := make(map[string]string, len(detailed))
	for name, value := range detailed {
		switch {
		case value == "ok":
			checks[name] = "ok"
		case degradedNames[name]:
			checks[name] = "degraded"
		default:
			checks[name] = "failed"
		}
	}
	result := publicReadinessResult{ready: ready, checks: checks, degraded: degraded}
	r.publicMu.Lock()
	r.publicResult = &result
	r.publicValidTil = time.Now().Add(publicReadinessCacheTTL)
	r.publicMu.Unlock()
	return result
}

// Handler serves GET /readyz: 200 with per-dependency status when ready, 503 when
// any dependency is down. Public checks return only ok, degraded, or failed.
func (r *Readiness) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		result, available := r.publicEvaluation(req.Context())
		if !available {
			return
		}
		status := http.StatusOK
		overall := "ok"
		if !result.ready {
			status = http.StatusServiceUnavailable
			overall = "degraded"
		}
		body := map[string]any{"status": overall, "checks": result.checks}
		if len(result.degraded) > 0 {
			// Ready, but these probes were shed by load: 200 keeps the replica in
			// rotation while the list makes the shedding visible and alertable.
			body["degraded"] = result.degraded
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}
