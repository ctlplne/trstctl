package observ_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/observ"
)

// TestReadinessAllUp: when every dependency probe succeeds, readiness is 200.
func TestReadinessAllUp(t *testing.T) {
	r := observ.NewReadiness(observ.NewTracer(nil),
		observ.Check{Name: "db", Probe: func(context.Context) error { return nil }},
		observ.Check{Name: "nats", Probe: func(context.Context) error { return nil }},
		observ.Check{Name: "signer", Probe: func(context.Context) error { return nil }},
	)
	rec := httptest.NewRecorder()
	r.Handler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readiness all-up = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestReadinessDepDownFlips503 is the R2.2 acceptance "readiness flips correctly
// when a dependency is down": a failing probe makes /readyz return 503 and names
// the failed dependency.
func TestReadinessDepDownFlips503(t *testing.T) {
	r := observ.NewReadiness(observ.NewTracer(nil),
		observ.Check{Name: "db", Probe: func(context.Context) error { return nil }},
		observ.Check{Name: "signer", Probe: func(context.Context) error { return errors.New("signer unreachable") }},
	)
	rec := httptest.NewRecorder()
	r.Handler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness with a dependency down = %d, want 503", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "signer") {
		t.Errorf("readiness body should name the failed dependency: %s", body)
	}
}

// TestReadinessEmitsChildSpans: each dependency probe runs under a child span of
// the request, so a /readyz call produces a trace spanning the real subsystems
// (DB, NATS, signer).
func TestReadinessEmitsChildSpans(t *testing.T) {
	exp := &capture{}
	tr := observ.NewTracer(exp)
	// Seed the request context with a root span, as the middleware would.
	ctx, root := tr.Start(context.Background(), "http.request")
	r := observ.NewReadiness(tr,
		observ.Check{Name: "db", Probe: func(context.Context) error { return nil }},
		observ.Check{Name: "nats", Probe: func(context.Context) error { return nil }},
	)
	rec := httptest.NewRecorder()
	r.Handler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx))
	root.End()

	spans := exp.all()
	var dbChild, natsChild bool
	for _, s := range spans {
		if s.TraceID != root.Context().TraceID {
			continue
		}
		if strings.Contains(s.Name, "db") {
			dbChild = true
		}
		if strings.Contains(s.Name, "nats") {
			natsChild = true
		}
	}
	if !dbChild || !natsChild {
		t.Errorf("expected db and nats child spans under the request trace; got %d spans", len(spans))
	}
}
