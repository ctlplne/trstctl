// Package observ is trstctl's observability baseline: a dependency-free metrics
// registry that renders the Prometheus text exposition format, W3C-traceparent
// distributed tracing with a pluggable exporter (OTLP-export is a follow-up), and
// HTTP middleware that ties request metrics, tracing, and structured logging
// together — wired into the serving path so an operator can answer "is it
// healthy, and if not, where does it hurt" from telemetry alone (B6).
package observ

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds the process's metrics and renders them in the Prometheus text
// exposition format. It is safe for concurrent use.
type Registry struct {
	mu       sync.Mutex
	counters []*CounterVec
	histos   []*HistogramVec
	gauges   []*Gauge
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// CounterVec is a set of monotonically increasing counters partitioned by a label
// tuple. Registering the same name twice returns the existing vector.
type CounterVec struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	series     map[string]*Counter
	order      []string
}

// Counter is a single counter series.
type Counter struct {
	labelValues []string
	bits        atomic.Uint64 // float64 bits
}

// Inc adds one. Add adds f (f should be >= 0 for a counter).
func (c *Counter) Inc() { c.Add(1) }

// Add adds f to the counter.
func (c *Counter) Add(f float64) {
	for {
		old := c.bits.Load()
		nv := math.Float64frombits(old) + f
		if c.bits.CompareAndSwap(old, math.Float64bits(nv)) {
			return
		}
	}
}

func (c *Counter) value() float64 { return math.Float64frombits(c.bits.Load()) }

// CounterVec registers (or returns) a counter vector.
func (r *Registry) CounterVec(name, help string, labels []string) *CounterVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, cv := range r.counters {
		if cv.name == name {
			return cv
		}
	}
	cv := &CounterVec{name: name, help: help, labels: labels, series: map[string]*Counter{}}
	r.counters = append(r.counters, cv)
	return cv
}

// WithLabelValues returns the counter for the given label values (creating it on
// first use). The values must align with the vector's label names.
func (cv *CounterVec) WithLabelValues(vals ...string) *Counter {
	key := strings.Join(vals, "\x1f")
	cv.mu.Lock()
	defer cv.mu.Unlock()
	if c, ok := cv.series[key]; ok {
		return c
	}
	c := &Counter{labelValues: append([]string(nil), vals...)}
	cv.series[key] = c
	cv.order = append(cv.order, key)
	return c
}

// Gauge is a single value that can go up or down.
type Gauge struct {
	name, help string
	bits       atomic.Uint64
}

// Gauge registers (or returns) a gauge.
func (r *Registry) Gauge(name, help string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, g := range r.gauges {
		if g.name == name {
			return g
		}
	}
	g := &Gauge{name: name, help: help}
	r.gauges = append(r.gauges, g)
	return g
}

// Set sets the gauge value.
func (g *Gauge) Set(f float64) { g.bits.Store(math.Float64bits(f)) }

func (g *Gauge) value() float64 { return math.Float64frombits(g.bits.Load()) }

// HistogramVec is a set of histograms partitioned by a label tuple.
type HistogramVec struct {
	name, help string
	buckets    []float64 // ascending, excluding +Inf
	labels     []string
	mu         sync.Mutex
	series     map[string]*Histogram
	order      []string
}

// Histogram is a single histogram series.
type Histogram struct {
	labelValues []string
	mu          sync.Mutex
	counts      []uint64 // len == len(buckets)+1 (last is the +Inf overflow)
	sum         float64
	buckets     []float64
}

// HistogramVec registers (or returns) a histogram vector.
func (r *Registry) HistogramVec(name, help string, buckets []float64, labels []string) *HistogramVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, hv := range r.histos {
		if hv.name == name {
			return hv
		}
	}
	hv := &HistogramVec{name: name, help: help, buckets: buckets, labels: labels, series: map[string]*Histogram{}}
	r.histos = append(r.histos, hv)
	return hv
}

// WithLabelValues returns the histogram for the given label values.
func (hv *HistogramVec) WithLabelValues(vals ...string) *Histogram {
	key := strings.Join(vals, "\x1f")
	hv.mu.Lock()
	defer hv.mu.Unlock()
	if h, ok := hv.series[key]; ok {
		return h
	}
	h := &Histogram{labelValues: append([]string(nil), vals...), counts: make([]uint64, len(hv.buckets)+1), buckets: hv.buckets}
	hv.series[key] = h
	hv.order = append(hv.order, key)
	return h
}

// Observe records one sample.
func (h *Histogram) Observe(f float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += f
	for i, b := range h.buckets {
		if f <= b {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.buckets)]++ // +Inf
}

// WriteProm writes the registry in the Prometheus text exposition format.
func (r *Registry) WriteProm(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	bw := bufio.NewWriter(w)
	// bufio.Writer accumulates a sticky error surfaced by Flush, so per-line
	// errors are discarded explicitly here and reported once at the end.
	pf := func(format string, a ...any) { _, _ = fmt.Fprintf(bw, format, a...) }

	for _, cv := range r.counters {
		pf("# HELP %s %s\n# TYPE %s counter\n", cv.name, cv.help, cv.name)
		cv.mu.Lock()
		for _, key := range cv.order {
			c := cv.series[key]
			pf("%s%s %s\n", cv.name, renderLabels(cv.labels, c.labelValues), formatFloat(c.value()))
		}
		cv.mu.Unlock()
	}
	for _, g := range r.gauges {
		pf("# HELP %s %s\n# TYPE %s gauge\n%s %s\n", g.name, g.help, g.name, g.name, formatFloat(g.value()))
	}
	for _, hv := range r.histos {
		pf("# HELP %s %s\n# TYPE %s histogram\n", hv.name, hv.help, hv.name)
		hv.mu.Lock()
		for _, key := range hv.order {
			h := hv.series[key]
			h.mu.Lock()
			var cum uint64
			for i, b := range hv.buckets {
				cum += h.counts[i]
				pf("%s_bucket%s %d\n", hv.name, renderLabelsLE(hv.labels, h.labelValues, formatFloat(b)), cum)
			}
			cum += h.counts[len(hv.buckets)]
			pf("%s_bucket%s %d\n", hv.name, renderLabelsLE(hv.labels, h.labelValues, "+Inf"), cum)
			pf("%s_sum%s %s\n", hv.name, renderLabels(hv.labels, h.labelValues), formatFloat(h.sum))
			pf("%s_count%s %d\n", hv.name, renderLabels(hv.labels, h.labelValues), cum)
			h.mu.Unlock()
		}
		hv.mu.Unlock()
	}
	return bw.Flush()
}

// Handler serves the registry at GET /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WriteProm(w)
	})
}

func renderLabels(names, values []string) string {
	if len(names) == 0 || len(values) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i >= len(values) {
			break
		}
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, n, escapeLabelValue(values[i]))
	}
	b.WriteByte('}')
	return b.String()
}

// renderLabelsLE renders the user labels with an appended le="…" label (for
// histogram buckets).
func renderLabelsLE(names, values []string, le string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i >= len(values) {
			break
		}
		fmt.Fprintf(&b, `%s="%s",`, n, escapeLabelValue(values[i]))
	}
	fmt.Fprintf(&b, `le="%s"}`, le)
	return b.String()
}

func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func formatFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
