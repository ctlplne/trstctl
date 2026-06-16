package observ_test

import (
	"net/http"
	"net/http/httptest"
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
