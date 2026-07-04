// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/observ"
)

// COMP-02 acceptance: the served control plane streams both HTTP traces and
// event-sourced audit events to a real OTLP/HTTP collector payload. The collector
// decodes protobuf OTLP requests, so this catches library-only exporters that are
// not wired into the running server path.
func TestServedOTLPExporterStreamsTracesAndAuditEvents(t *testing.T) {
	collector := newServedOTLPCapture(t)
	exp, err := observ.NewOTLPHTTPExporter(observ.OTLPConfig{
		Endpoint:    collector.URL(),
		Insecure:    true,
		ServiceName: "trstctl-test",
	})
	if err != nil {
		t.Fatalf("build OTLP exporter: %v", err)
	}
	t.Cleanup(func() { _ = exp.Close() })
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OTLPExporter = exp
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.srv.RunOTLPAuditStream(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("OTLP audit streamer did not stop")
		}
	})

	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "otlp-operator", []string{
		string(authz.OwnersWrite),
	})
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "comp-02-owner", map[string]string{
		"kind": "workload",
		"name": "otlp-observed-owner",
	})
	if code != http.StatusCreated {
		t.Fatalf("create owner = %d body=%s; want 201", code, body)
	}

	collector.WaitTrace(t, func(req *coltracepb.ExportTraceServiceRequest) bool {
		for _, span := range otlpSpans(req) {
			if span.GetName() == "http.request" &&
				otlpAttr(span.GetAttributes(), "http.route") == "/api/v1/owners" &&
				otlpAttr(span.GetAttributes(), "http.status_code") == "201" {
				return true
			}
		}
		return false
	})
	collector.WaitLog(t, func(req *collogspb.ExportLogsServiceRequest) bool {
		for _, rec := range otlpLogRecords(req) {
			if otlpString(rec.GetBody()) == "owner.created" &&
				otlpAttr(rec.GetAttributes(), "trstctl.audit.type") == "owner.created" &&
				otlpAttr(rec.GetAttributes(), "trstctl.tenant.id") == h.tenant &&
				otlpAttr(rec.GetAttributes(), "trstctl.audit.sequence") != "" {
				return true
			}
		}
		return false
	})
}

type servedOTLPCapture struct {
	ts     *httptest.Server
	traces chan *coltracepb.ExportTraceServiceRequest
	logs   chan *collogspb.ExportLogsServiceRequest
}

func newServedOTLPCapture(t *testing.T) *servedOTLPCapture {
	t.Helper()
	c := &servedOTLPCapture{
		traces: make(chan *coltracepb.ExportTraceServiceRequest, 32),
		logs:   make(chan *collogspb.ExportLogsServiceRequest, 32),
	}
	c.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/v1/traces":
			var req coltracepb.ExportTraceServiceRequest
			if err := proto.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			c.traces <- &req
		case "/v1/logs":
			var req collogspb.ExportLogsServiceRequest
			if err := proto.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			c.logs <- &req
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.ts.Close)
	return c
}

func (c *servedOTLPCapture) URL() string { return c.ts.URL }

func (c *servedOTLPCapture) WaitTrace(t *testing.T, match func(*coltracepb.ExportTraceServiceRequest) bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case req := <-c.traces:
			if match(req) {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for matching OTLP trace export")
		}
	}
}

func (c *servedOTLPCapture) WaitLog(t *testing.T, match func(*collogspb.ExportLogsServiceRequest) bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case req := <-c.logs:
			if match(req) {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for matching OTLP log export")
		}
	}
}

func otlpSpans(req *coltracepb.ExportTraceServiceRequest) []*tracepb.Span {
	var out []*tracepb.Span
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			out = append(out, ss.GetSpans()...)
		}
	}
	return out
}

func otlpLogRecords(req *collogspb.ExportLogsServiceRequest) []*logspb.LogRecord {
	var out []*logspb.LogRecord
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			out = append(out, sl.GetLogRecords()...)
		}
	}
	return out
}

func otlpAttr(attrs []*commonpb.KeyValue, key string) string {
	for _, kv := range attrs {
		if kv.GetKey() == key {
			return otlpString(kv.GetValue())
		}
	}
	return ""
}

func otlpString(v *commonpb.AnyValue) string {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	default:
		return ""
	}
}
