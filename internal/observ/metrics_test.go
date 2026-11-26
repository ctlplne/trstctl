// SPDX-License-Identifier: BUSL-1.1

package observ_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/observ"
)

// TestCounterPromText: counters accumulate by label set and render in the
// Prometheus text exposition format.
func TestCounterPromText(t *testing.T) {
	reg := observ.NewRegistry()
	c := reg.CounterVec("trstctl_test_total", "a test counter", []string{"code"})
	c.WithLabelValues("200").Inc()
	c.WithLabelValues("200").Inc()
	c.WithLabelValues("500").Add(3)

	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"# HELP trstctl_test_total a test counter",
		"# TYPE trstctl_test_total counter",
		`trstctl_test_total{code="200"} 2`,
		`trstctl_test_total{code="500"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("WriteProm output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestMetricVectorsBoundUntrustedLabelsAndSeries(t *testing.T) {
	r := observ.NewRegistry()
	c := r.CounterVec("trstctl_untrusted_total", "test", []string{"input"})
	h := r.HistogramVec("trstctl_untrusted_seconds", "test", []float64{1}, []string{"input"})
	g := r.GaugeVec("trstctl_untrusted_value", "test", []string{"input"})
	c.WithLabelValues("__overflow__").Inc() // caller cannot claim the reserved overflow label
	h.WithLabelValues("__overflow__").Observe(0.1)
	g.WithLabelValues("__overflow__").Set(1)
	for i := 0; i < 3000; i++ {
		v := "attacker-" + strconv.Itoa(i)
		c.WithLabelValues(v).Inc()
		h.WithLabelValues(v).Observe(0.1)
		g.WithLabelValues(v).Set(1)
	}
	for _, v := range []string{strings.Repeat("a", 128<<10), "bad\xff", "bad\rvalue"} {
		c.WithLabelValues(v).Inc()
		h.WithLabelValues(v).Observe(0.1)
		g.WithLabelValues(v).Set(1)
	}
	var out strings.Builder
	if err := r.WriteProm(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "trstctl_untrusted_total{") > 2052 ||
		strings.Count(out.String(), "trstctl_untrusted_seconds_count{") > 2052 ||
		strings.Count(out.String(), "trstctl_untrusted_value{") > 2052 {
		t.Fatal("metric vector accepted unbounded series")
	}
	if strings.Contains(out.String(), strings.Repeat("a", 100)) || strings.Contains(out.String(), "\xff") || strings.Contains(out.String(), "\r") {
		t.Fatal("metric vector retained an unsafe label")
	}
	if strings.Count(out.String(), `trstctl_untrusted_total{input="__overflow__"}`) != 1 {
		t.Fatal("overflow label is missing or collides with caller-controlled label")
	}
}

// TestHistogramPromText: histograms render cumulative buckets, _sum, and _count.
func TestHistogramPromText(t *testing.T) {
	reg := observ.NewRegistry()
	h := reg.HistogramVec("trstctl_test_seconds", "durations", []float64{0.1, 1}, []string{"route"})
	h.WithLabelValues("/x").Observe(0.05)
	h.WithLabelValues("/x").Observe(0.5)

	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"# TYPE trstctl_test_seconds histogram",
		`trstctl_test_seconds_bucket{route="/x",le="0.1"} 1`,
		`trstctl_test_seconds_bucket{route="/x",le="1"} 2`,
		`trstctl_test_seconds_bucket{route="/x",le="+Inf"} 2`,
		`trstctl_test_seconds_count{route="/x"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("WriteProm output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// TestGaugePromText: gauges render their set value.
func TestGaugePromText(t *testing.T) {
	reg := observ.NewRegistry()
	g := reg.Gauge("trstctl_test_ready", "1 when ready")
	g.Set(1)

	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, "# TYPE trstctl_test_ready gauge") || !strings.Contains(out, "trstctl_test_ready 1") {
		t.Errorf("gauge not rendered:\n%s", out)
	}
}

// TestGaugeVecPromText: labeled gauges render one series per label set.
func TestGaugeVecPromText(t *testing.T) {
	reg := observ.NewRegistry()
	g := reg.GaugeVec("trstctl_test_depth", "queue depth", []string{"subsystem"})
	g.WithLabelValues("api").Set(2)
	g.WithLabelValues("outbox").Set(7)

	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"# TYPE trstctl_test_depth gauge",
		`trstctl_test_depth{subsystem="api"} 2`,
		`trstctl_test_depth{subsystem="outbox"} 7`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("WriteProm output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// TestMetricsHandler: the /metrics handler serves the exposition over HTTP.
func TestMetricsHandler(t *testing.T) {
	reg := observ.NewRegistry()
	reg.CounterVec("trstctl_x_total", "x", nil).WithLabelValues().Inc()

	srv := httptest.NewServer(reg.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type %q, want text/plain", ct)
	}
}
