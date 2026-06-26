package observ

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"trstctl.com/trstctl/internal/events"
)

const (
	OTLPSemConvVersion = "1.27.0"
	OTLPSchemaURL      = "https://opentelemetry.io/schemas/" + OTLPSemConvVersion
	OTLPScopeName      = "trstctl"
	OTLPScopeVersion   = OTLPSemConvVersion

	defaultOTLPTimeout      = 5 * time.Second
	defaultOTLPQueueSize    = 1024
	defaultOTLPAuditPoll    = 500 * time.Millisecond
	otlpContentTypeProtobuf = "application/x-protobuf"
)

// OTLPConfig configures OTLP/HTTP export to an operator-owned collector.
type OTLPConfig struct {
	Endpoint    string
	Token       []byte
	Insecure    bool
	ServiceName string
	Timeout     time.Duration
	QueueSize   int
	Client      *http.Client
}

// OTLPExporter exports served traces and audit events as OTLP/HTTP protobuf.
type OTLPExporter struct {
	endpoint    string
	token       []byte
	client      *http.Client
	serviceName string
	timeout     time.Duration

	traces chan SpanData
	stop   chan struct{}
	done   chan struct{}
	closed atomic.Bool
	once   sync.Once
	drops  atomic.Uint64
}

// NewOTLPHTTPExporter builds a bounded OTLP/HTTP exporter. Plaintext HTTP is
// allowed only when Insecure is true, so production cannot accidentally send
// telemetry over cleartext.
func NewOTLPHTTPExporter(cfg OTLPConfig) (*OTLPExporter, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("otlp: endpoint is required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("otlp: endpoint %q must be an absolute URL", cfg.Endpoint)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !cfg.Insecure {
			return nil, fmt.Errorf("otlp: plaintext endpoint %q requires insecure=true", cfg.Endpoint)
		}
	default:
		return nil, fmt.Errorf("otlp: endpoint scheme %q is not supported", u.Scheme)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultOTLPTimeout
	}
	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultOTLPQueueSize
	}
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "trstctl"
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Transport: cloneDefaultTransport()}
	}
	exp := &OTLPExporter{
		endpoint:    strings.TrimRight(cfg.Endpoint, "/"),
		token:       append([]byte(nil), cfg.Token...),
		client:      client,
		serviceName: serviceName,
		timeout:     timeout,
		traces:      make(chan SpanData, queueSize),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	go exp.runTraceWorker()
	return exp, nil
}

func cloneDefaultTransport() http.RoundTripper {
	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		return tr.Clone()
	}
	return http.DefaultTransport
}

// Export queues a completed span without blocking the served request path. When
// the queue is full the span is dropped; this preserves API backpressure and the
// collector can alert on missing telemetry by comparing audit/event sequences.
func (e *OTLPExporter) Export(span SpanData) {
	if e == nil || e.closed.Load() {
		return
	}
	select {
	case e.traces <- span:
	default:
		e.drops.Add(1)
	}
}

// DroppedSpans returns spans dropped because the bounded export queue was full.
func (e *OTLPExporter) DroppedSpans() uint64 {
	if e == nil {
		return 0
	}
	return e.drops.Load()
}

// Close stops the trace worker after draining queued spans.
func (e *OTLPExporter) Close() error {
	if e == nil {
		return nil
	}
	e.once.Do(func() {
		e.closed.Store(true)
		close(e.stop)
		<-e.done
		zero(e.token)
	})
	return nil
}

func (e *OTLPExporter) runTraceWorker() {
	defer close(e.done)
	for {
		select {
		case span := <-e.traces:
			e.exportSpanWithTimeout(span)
		case <-e.stop:
			for {
				select {
				case span := <-e.traces:
					e.exportSpanWithTimeout(span)
				default:
					return
				}
			}
		}
	}
}

func (e *OTLPExporter) exportSpanWithTimeout(span SpanData) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	_ = e.ExportTraces(ctx, span)
}

// ExportTraces sends a completed trstctl span as an OTLP trace export.
func (e *OTLPExporter) ExportTraces(ctx context.Context, span SpanData) error {
	if e == nil {
		return nil
	}
	req := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		SchemaUrl: OTLPSchemaURL,
		Resource:  e.resource("traces"),
		ScopeSpans: []*tracepb.ScopeSpans{{
			SchemaUrl: OTLPSchemaURL,
			Scope:     instrumentationScope(),
			Spans:     []*tracepb.Span{otlpSpan(span)},
		}},
	}}}
	return e.post(ctx, e.signalURL("traces"), req)
}

// ExportEvent sends one event-sourced audit event as an OTLP log record.
func (e *OTLPExporter) ExportEvent(ctx context.Context, ev events.Event) error {
	if e == nil {
		return nil
	}
	rec := &logspb.LogRecord{
		TimeUnixNano: uint64(ev.Time.UnixNano()),
		SeverityText: "INFO",
		Body:         stringValue(ev.Type),
		Attributes: []*commonpb.KeyValue{
			stringKV("trstctl.audit.type", ev.Type),
			stringKV("trstctl.audit.id", ev.ID),
			stringKV("trstctl.audit.sequence", strconv.FormatUint(ev.Sequence, 10)),
			stringKV("trstctl.audit.schema_version", strconv.Itoa(ev.SchemaVersion)),
			stringKV("trstctl.tenant.id", ev.TenantID),
			stringKV("trstctl.audit.payload_bytes", strconv.Itoa(len(ev.Data))),
		},
	}
	if ev.Actor != nil {
		rec.Attributes = append(rec.Attributes, stringKV("trstctl.audit.actor.subject", ev.Actor.Subject))
		if len(ev.Actor.Roles) > 0 {
			rec.Attributes = append(rec.Attributes, stringKV("trstctl.audit.actor.roles", strings.Join(ev.Actor.Roles, ",")))
		}
	}
	req := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		SchemaUrl: OTLPSchemaURL,
		Resource:  e.resource("audit"),
		ScopeLogs: []*logspb.ScopeLogs{{
			SchemaUrl:  OTLPSchemaURL,
			Scope:      instrumentationScope(),
			LogRecords: []*logspb.LogRecord{rec},
		}},
	}}}
	return e.post(ctx, e.signalURL("logs"), req)
}

func (e *OTLPExporter) resource(signal string) *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		stringKV("service.name", e.serviceName),
		stringKV("trstctl.signal", signal),
	}}
}

func (e *OTLPExporter) post(ctx context.Context, target string, msg proto.Message) error {
	body, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("otlp: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", otlpContentTypeProtobuf)
	if len(e.token) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(e.token))
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp: export rejected by collector: %s", resp.Status)
	}
	return nil
}

func (e *OTLPExporter) signalURL(signal string) string {
	u := strings.TrimRight(e.endpoint, "/")
	for _, s := range []string{"metrics", "traces", "logs"} {
		if strings.HasSuffix(u, "/v1/"+s) {
			return strings.TrimSuffix(u, "/v1/"+s) + "/v1/" + signal
		}
	}
	if strings.HasSuffix(u, "/"+signal) {
		return u
	}
	return u + "/v1/" + signal
}

func otlpSpan(span SpanData) *tracepb.Span {
	out := &tracepb.Span{
		TraceId:           hexBytes(span.TraceID),
		SpanId:            hexBytes(span.SpanID),
		ParentSpanId:      hexBytes(span.ParentID),
		Name:              span.Name,
		Kind:              tracepb.Span_SPAN_KIND_SERVER,
		StartTimeUnixNano: uint64(span.Start.UnixNano()),
		EndTimeUnixNano:   uint64(span.End.UnixNano()),
	}
	keys := make([]string, 0, len(span.Attrs))
	for k := range span.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "" {
			continue
		}
		out.Attributes = append(out.Attributes, stringKV(k, span.Attrs[k]))
	}
	return out
}

func hexBytes(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func instrumentationScope() *commonpb.InstrumentationScope {
	return &commonpb.InstrumentationScope{Name: OTLPScopeName, Version: OTLPScopeVersion}
}

func stringKV(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: stringValue(value)}
}

func stringValue(value string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// OTLPAuditStreamer tails the event log and exports events as OTLP log records.
type OTLPAuditStreamer struct {
	log      *events.Log
	exporter *OTLPExporter
	next     uint64
	poll     time.Duration
}

// NewOTLPAuditStreamer returns an event-log tailer for OTLP audit streaming.
func NewOTLPAuditStreamer(log *events.Log, exporter *OTLPExporter) *OTLPAuditStreamer {
	return &OTLPAuditStreamer{log: log, exporter: exporter, next: 1, poll: defaultOTLPAuditPoll}
}

// Run exports new event-log records until ctx is cancelled.
func (s *OTLPAuditStreamer) Run(ctx context.Context) error {
	if s == nil || s.log == nil || s.exporter == nil {
		return nil
	}
	t := time.NewTicker(s.poll)
	defer t.Stop()
	for {
		if _, err := s.ExportOnce(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// ExportOnce exports any events from the current cursor through the current head.
func (s *OTLPAuditStreamer) ExportOnce(ctx context.Context) (int, error) {
	if s == nil || s.log == nil || s.exporter == nil {
		return 0, nil
	}
	exported := 0
	err := s.log.Replay(ctx, s.next, func(ev events.Event) error {
		if err := s.exporter.ExportEvent(ctx, ev); err != nil {
			return err
		}
		s.next = ev.Sequence + 1
		exported++
		return nil
	})
	return exported, err
}
