package projections_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/server"
)

// syncBuf is a concurrency-safe log sink (httptest serves each request in its own
// goroutine).
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type spanCap struct {
	mu    sync.Mutex
	spans []observ.SpanData
}

func (c *spanCap) Export(s observ.SpanData) {
	c.mu.Lock()
	c.spans = append(c.spans, s)
	c.mu.Unlock()
}
func (c *spanCap) all() []observ.SpanData {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]observ.SpanData(nil), c.spans...)
}

// TestAssembledServerObservability is the R2.2 disconfirming test for B6
// (observability): against the assembled control plane, /metrics serves
// Prometheus metrics, /readyz covers the real dependencies (DB, NATS, signer), a
// request produces a trace spanning those subsystems under one trace id, and
// structured logs carry a correlation id while leaking no secret material.
func TestAssembledServerObservability(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	logBuf := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logBuf, nil))
	exp := &spanCap{}

	asm, err := server.Build(context.Background(), server.Deps{
		Store: st, Log: log, Signer: prov, Logger: logger, TraceExporter: exp,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	// Readiness covers DB, NATS, and the signer — all up here.
	if code, body := req(t, ts, http.MethodGet, "/readyz", "", ""); code != http.StatusOK {
		t.Fatalf("/readyz = %d, want 200 (it must cover the real deps): %s", code, body)
	}

	// /metrics exposes the request metrics in Prometheus text format.
	code, body := req(t, ts, http.MethodGet, "/metrics", "", "")
	if code != http.StatusOK {
		t.Fatalf("/metrics = %d, want 200", code)
	}
	if !strings.Contains(string(body), "trstctl_http_requests_total") {
		t.Errorf("/metrics is missing the request counter:\n%s", body)
	}

	// The /readyz request produced a trace spanning the real subsystems: a root
	// span plus db/nats/signer children, all sharing one trace id.
	if !traceSpansSubsystems(exp.all()) {
		t.Error("no end-to-end trace spanning db/nats/signer under a single trace id")
	}

	// A token-authenticated request: logs carry a correlation id and never leak
	// the token (AN-8).
	token := mintToken(t, st, "owners:read")
	req(t, ts, http.MethodGet, "/api/v1/owners", token, "")
	logs := logBuf.String()
	if !strings.Contains(logs, "trace_id") {
		t.Errorf("structured logs are missing the trace_id correlation field:\n%s", logs)
	}
	if strings.Contains(logs, token) {
		t.Error("the API token leaked into the structured logs")
	}
}

func traceSpansSubsystems(spans []observ.SpanData) bool {
	byTrace := map[string]map[string]bool{}
	for _, s := range spans {
		if byTrace[s.TraceID] == nil {
			byTrace[s.TraceID] = map[string]bool{}
		}
		byTrace[s.TraceID][s.Name] = true
	}
	for _, names := range byTrace {
		var db, nats, signer bool
		for n := range names {
			switch {
			case strings.Contains(n, "db"):
				db = true
			case strings.Contains(n, "nats"):
				nats = true
			case strings.Contains(n, "signer"):
				signer = true
			}
		}
		if db && nats && signer && len(names) >= 2 {
			return true
		}
	}
	return false
}
