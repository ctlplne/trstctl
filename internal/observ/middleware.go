package observ

import (
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultBuckets are latency histogram buckets in seconds.
var defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Options configures the HTTP observability middleware.
type Options struct {
	Logger   *slog.Logger // structured request log sink; a nil logger discards
	Tracer   *Tracer      // distributed tracing; nil yields a no-op tracer
	Registry *Registry    // metrics sink; nil disables request metrics
}

// Middleware instruments HTTP requests with tracing, metrics, and a structured
// access log. It records ZERO secret material: it logs the method, the normalized
// route, and the status — never the Authorization header, the body, or the query
// string (AN-8).
type Middleware struct {
	logger *slog.Logger
	tracer *Tracer
	reqs   *CounterVec
	dur    *HistogramVec
}

// NewMiddleware builds the middleware from opts.
func NewMiddleware(opts Options) *Middleware {
	m := &Middleware{logger: opts.Logger, tracer: opts.Tracer}
	if m.logger == nil {
		m.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if m.tracer == nil {
		m.tracer = NewTracer(nil)
	}
	if opts.Registry != nil {
		m.reqs = opts.Registry.CounterVec("trstctl_http_requests_total",
			"Total HTTP requests by method, route, and status code.", []string{"method", "route", "code"})
		m.dur = opts.Registry.HistogramVec("trstctl_http_request_duration_seconds",
			"HTTP request latency in seconds by method and route.", defaultBuckets, []string{"method", "route"})
	}
	return m
}

// Handler wraps next with tracing, metrics, and access logging.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Continue an inbound trace if present, else start a fresh one.
		parent, _ := ParseTraceparent(r.Header.Get("traceparent"))
		ctx, span := m.tracer.StartFrom(r.Context(), parent, "http.request")
		route := normalizeRoute(r.URL.Path)
		span.SetAttr("http.method", r.Method)
		span.SetAttr("http.route", route)

		// Hand the trace context back to the caller so the request is traceable
		// end to end across hops.
		w.Header().Set("traceparent", span.Context().Traceparent())

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))

		elapsed := time.Since(start)
		code := strconv.Itoa(rec.status)
		span.SetAttr("http.status_code", code)
		span.End()

		if m.reqs != nil {
			m.reqs.WithLabelValues(r.Method, route, code).Inc()
			m.dur.WithLabelValues(r.Method, route).Observe(elapsed.Seconds())
		}

		level := slog.LevelInfo
		if rec.status >= 500 {
			level = slog.LevelError
		}
		// Redacted by construction: only method, normalized route, status, size,
		// duration, and the correlation id — never credentials, body, or query.
		m.logger.LogAttrs(ctx, level, "http_request",
			slog.String("trace_id", span.Context().TraceID),
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.Int("status", rec.status),
			slog.Int("bytes", rec.bytes),
			slog.Int64("duration_ms", elapsed.Milliseconds()),
		)
	})
}

// statusRecorder captures the response status and size.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wrote = true
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe  = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	numRe  = regexp.MustCompile(`^[0-9]+$`)
)

// normalizeRoute collapses high-cardinality path segments (UUIDs, long hex ids,
// numeric ids) into ":id" so per-id paths do not explode metric/label cardinality
// — and so no opaque identifier leaks into a label.
func normalizeRoute(path string) string {
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		if uuidRe.MatchString(s) || hexRe.MatchString(s) || numRe.MatchString(s) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}
