package observ

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// SpanContext identifies a span within a trace, in the W3C Trace Context shape so
// it interoperates with OpenTelemetry/Jaeger collectors on the wire (via the
// traceparent header). A future PR can add an OTLP exporter behind the Exporter
// seam without changing callers.
type SpanContext struct {
	TraceID string // 16-byte trace id, hex (32 chars)
	SpanID  string // 8-byte span id, hex (16 chars)
	Sampled bool
}

// Valid reports whether the context has a non-empty trace and span id.
func (sc SpanContext) Valid() bool { return len(sc.TraceID) == 32 && len(sc.SpanID) == 16 }

// Traceparent renders the W3C traceparent header value.
func (sc SpanContext) Traceparent() string {
	flags := "00"
	if sc.Sampled {
		flags = "01"
	}
	return "00-" + sc.TraceID + "-" + sc.SpanID + "-" + flags
}

// ParseTraceparent parses a W3C traceparent header. It returns false for any
// malformed value (so a bad inbound header just starts a fresh trace).
func ParseTraceparent(s string) (SpanContext, bool) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) != 4 || parts[0] != "00" {
		return SpanContext{}, false
	}
	if !isHex(parts[1], 32) || !isHex(parts[2], 16) || !isHex(parts[3], 2) {
		return SpanContext{}, false
	}
	flags, err := hex.DecodeString(parts[3])
	if err != nil {
		return SpanContext{}, false
	}
	return SpanContext{TraceID: parts[1], SpanID: parts[2], Sampled: flags[0]&0x01 == 0x01}, true
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// SpanData is a completed span handed to an Exporter.
type SpanData struct {
	TraceID  string
	SpanID   string
	ParentID string
	Name     string
	Start    time.Time
	End      time.Time
	Attrs    map[string]string
}

// Duration is the span's elapsed time.
func (s SpanData) Duration() time.Duration { return s.End.Sub(s.Start) }

// Exporter receives completed spans. The nil exporter is a no-op.
type Exporter interface {
	Export(SpanData)
}

// Tracer creates spans and hands completed ones to its exporter.
type Tracer struct {
	exporter Exporter
}

// NewTracer returns a tracer that exports completed spans to exp (which may be
// nil for a no-op tracer).
func NewTracer(exp Exporter) *Tracer { return &Tracer{exporter: exp} }

// Span is an in-progress unit of work.
type Span struct {
	tracer   *Tracer
	sc       SpanContext
	parentID string
	name     string
	start    time.Time

	mu    sync.Mutex
	attrs map[string]string
	ended bool
}

// Start begins a span as a child of any span carried in ctx (continuing its
// trace), or a new root span otherwise. The returned context carries the new
// span so deeper calls become its children — this is how one trace spans a
// request across subsystems.
func (t *Tracer) Start(ctx context.Context, name string) (context.Context, *Span) {
	parent, ok := SpanContextFromContext(ctx)
	if ok && parent.Valid() {
		return t.StartFrom(ctx, parent, name)
	}
	return t.StartFrom(ctx, SpanContext{}, name)
}

// StartFrom begins a span as a child of an explicit parent context (for example
// one parsed from an inbound traceparent header). An invalid parent starts a new
// trace.
func (t *Tracer) StartFrom(ctx context.Context, parent SpanContext, name string) (context.Context, *Span) {
	traceID := parent.TraceID
	sampled := parent.Sampled
	parentSpan := parent.SpanID
	if !parent.Valid() {
		traceID = randHex(16)
		sampled = true
		parentSpan = ""
	}
	sc := SpanContext{TraceID: traceID, SpanID: randHex(8), Sampled: sampled}
	span := &Span{tracer: t, sc: sc, parentID: parentSpan, name: name, start: time.Now()}
	return ContextWithSpanContext(ctx, sc), span
}

// Context returns the span's context.
func (s *Span) Context() SpanContext { return s.sc }

// SetAttr records a non-secret attribute on the span.
func (s *Span) SetAttr(k, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attrs == nil {
		s.attrs = map[string]string{}
	}
	s.attrs[k] = v
}

// End completes the span and exports it (once).
func (s *Span) End() {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	attrs := s.attrs
	s.mu.Unlock()
	if s.tracer == nil || s.tracer.exporter == nil {
		return
	}
	s.tracer.exporter.Export(SpanData{
		TraceID: s.sc.TraceID, SpanID: s.sc.SpanID, ParentID: s.parentID,
		Name: s.name, Start: s.start, End: time.Now(), Attrs: attrs,
	})
}

type spanCtxKey struct{}

// ContextWithSpanContext returns a context carrying sc.
func ContextWithSpanContext(ctx context.Context, sc SpanContext) context.Context {
	return context.WithValue(ctx, spanCtxKey{}, sc)
}

// SpanContextFromContext returns the span context carried by ctx, if any.
func SpanContextFromContext(ctx context.Context) (SpanContext, bool) {
	sc, ok := ctx.Value(spanCtxKey{}).(SpanContext)
	return sc, ok
}

// TraceIDFromContext returns the current trace id, or "" if none.
func TraceIDFromContext(ctx context.Context) string {
	if sc, ok := SpanContextFromContext(ctx); ok {
		return sc.TraceID
	}
	return ""
}

var fallbackCounter atomic.Uint64

// randHex returns n random bytes as hex, sourced from the crypto boundary (AN-3).
// On the essentially-never RNG failure it falls back to a monotonic counter so an
// id is never empty.
func randHex(n int) string {
	b, err := crypto.RandomBytes(n)
	if err != nil || len(b) < n {
		b = make([]byte, n)
		v := fallbackCounter.Add(1)
		if n >= 8 {
			binary.BigEndian.PutUint64(b[n-8:], v)
		} else {
			for i := range b {
				b[i] = byte(v >> (8 * i))
			}
		}
	}
	return hex.EncodeToString(b)
}
