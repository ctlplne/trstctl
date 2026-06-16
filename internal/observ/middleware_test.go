package observ_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/observ"
)

// TestMiddlewareCorrelationAndRedaction is the R2.2 logging acceptance: the
// request-logging middleware emits a structured line carrying a correlation
// (trace) id and the route/status, sets a traceparent on the response, records
// request metrics — and leaks ZERO secret material (AN-8): not the bearer token,
// not the request body.
func TestMiddlewareCorrelationAndRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	reg := observ.NewRegistry()
	exp := &capture{}
	mw := observ.NewMiddleware(observ.Options{Logger: logger, Registry: reg, Tracer: observ.NewTracer(exp)})

	h := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/owners", strings.NewReader(`{"token":"S3CRET-BODY-VALUE"}`))
	req.Header.Set("Authorization", "Bearer trstctl_pat_SUPERSECRETTOKEN")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// The response carries the trace context for the caller to continue.
	if rec.Header().Get("traceparent") == "" {
		t.Error("response is missing a traceparent header")
	}

	line := buf.String()
	if !strings.Contains(line, "trace_id") {
		t.Errorf("structured log is missing the trace_id correlation field:\n%s", line)
	}
	if !strings.Contains(line, "/api/v1/owners") {
		t.Errorf("structured log is missing the route:\n%s", line)
	}
	if !strings.Contains(line, "201") {
		t.Errorf("structured log is missing the status:\n%s", line)
	}
	// AN-8: secret material must never appear in logs.
	if strings.Contains(line, "SUPERSECRETTOKEN") {
		t.Error("bearer token leaked into the structured log")
	}
	if strings.Contains(line, "S3CRET-BODY-VALUE") {
		t.Error("request body leaked into the structured log")
	}

	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "trstctl_http_requests_total") {
		t.Errorf("request metric not recorded:\n%s", sb.String())
	}
}

// TestMiddlewareContinuesInboundTrace: an inbound traceparent is continued onto
// the response (same trace id), so a request is traceable end to end across hops.
func TestMiddlewareContinuesInboundTrace(t *testing.T) {
	reg := observ.NewRegistry()
	mw := observ.NewMiddleware(observ.Options{Registry: reg, Tracer: observ.NewTracer(nil)})
	h := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	inbound := "00-" + strings.Repeat("a", 32) + "-" + strings.Repeat("b", 16) + "-01"
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", inbound)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	out := rec.Header().Get("traceparent")
	if !strings.Contains(out, strings.Repeat("a", 32)) {
		t.Errorf("response traceparent %q did not continue the inbound trace id", out)
	}
}
