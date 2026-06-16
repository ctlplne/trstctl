package observ_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/observ"
)

// capture is a thread-safe span exporter for tests.
type capture struct {
	mu    sync.Mutex
	spans []observ.SpanData
}

func (c *capture) Export(s observ.SpanData) {
	c.mu.Lock()
	c.spans = append(c.spans, s)
	c.mu.Unlock()
}

func (c *capture) all() []observ.SpanData {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]observ.SpanData(nil), c.spans...)
}

// TestTraceparentRoundTrip: the W3C traceparent header encodes and parses back.
func TestTraceparentRoundTrip(t *testing.T) {
	sc := observ.SpanContext{TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331", Sampled: true}
	tp := sc.Traceparent()
	if tp != "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01" {
		t.Fatalf("traceparent = %q", tp)
	}
	got, ok := observ.ParseTraceparent(tp)
	if !ok || got.TraceID != sc.TraceID || got.SpanID != sc.SpanID || !got.Sampled {
		t.Fatalf("parse = %+v, %v", got, ok)
	}
	if _, ok := observ.ParseTraceparent("not-a-traceparent"); ok {
		t.Error("parsed garbage as a traceparent")
	}
}

// TestChildSharesTraceID is the core of "a trace spans an end-to-end request": a
// child span carries its parent's trace id but a fresh span id, and the exporter
// records the parent linkage.
func TestChildSharesTraceID(t *testing.T) {
	exp := &capture{}
	tr := observ.NewTracer(exp)

	ctx, root := tr.Start(context.Background(), "root")
	rootTID := root.Context().TraceID
	if len(rootTID) != 32 {
		t.Fatalf("root trace id = %q (want 32 hex chars)", rootTID)
	}
	_, child := tr.Start(ctx, "child")
	if child.Context().TraceID != rootTID {
		t.Errorf("child trace id %s != root %s", child.Context().TraceID, rootTID)
	}
	if child.Context().SpanID == root.Context().SpanID {
		t.Error("child span id equals root span id")
	}
	child.End()
	root.End()

	spans := exp.all()
	if len(spans) != 2 {
		t.Fatalf("exporter saw %d spans, want 2", len(spans))
	}
	for _, s := range spans {
		if s.TraceID != rootTID {
			t.Errorf("span %q has trace id %s, want %s", s.Name, s.TraceID, rootTID)
		}
		if s.Name == "child" && s.ParentID != root.Context().SpanID {
			t.Errorf("child parent %s != root span %s", s.ParentID, root.Context().SpanID)
		}
	}
}

// TestStartFromContinuesIncomingTrace: an inbound traceparent is continued (same
// trace id, new server span id) — so a distributed trace flows in from a caller.
func TestStartFromContinuesIncomingTrace(t *testing.T) {
	tr := observ.NewTracer(nil) // a nil exporter is a no-op
	incoming := observ.SpanContext{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), Sampled: true}
	_, span := tr.StartFrom(context.Background(), incoming, "server")
	if span.Context().TraceID != incoming.TraceID {
		t.Errorf("server span trace id %s, want to continue %s", span.Context().TraceID, incoming.TraceID)
	}
	if span.Context().SpanID == incoming.SpanID {
		t.Error("server span reused the inbound span id")
	}
}
