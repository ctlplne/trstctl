package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/perf"
)

func TestSoakCaptureCommandWritesAnalyzerInput(t *testing.T) {
	dir := t.TempDir()
	seriesPath := filepath.Join(dir, "series.json")
	cmd := exec.Command("go", "run", ".", "--samples", "3", "--step-seconds", "60", "--load-samples", "4", "--no-sleep", "--pretty=false", "--out", seriesPath)
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(dir, "gocache"), "SOAK_CAPTURE_TEST_SAMPLER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("soakcapture failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(seriesPath)
	if err != nil {
		t.Fatalf("read series: %v", err)
	}
	var series perf.SoakSeries
	if err := json.Unmarshal(data, &series); err != nil {
		t.Fatalf("decode series: %v\n%s", err, data)
	}
	if len(series.Samples) != 3 || series.Source == "" {
		t.Fatalf("bad captured series: %+v", series)
	}
	for _, want := range []string{"served-routes", "embedded-postgres", "embedded-jetstream", "outbox", "metrics", "signer-rpc"} {
		if !strings.Contains(series.Source, want) {
			t.Fatalf("captured soak source = %q, want evidence for %s", series.Source, want)
		}
	}
	for i, sample := range series.Samples {
		if sample.DBPoolSize <= 1 {
			t.Fatalf("sample %d has placeholder DB pool size: %+v", i, sample)
		}
		if sample.ProjectionLagEvents <= 0 {
			t.Fatalf("sample %d did not capture event-log/projection lag: %+v", i, sample)
		}
		if sample.OutboxLagItems <= 0 {
			t.Fatalf("sample %d did not capture outbox backlog: %+v", i, sample)
		}
		if sample.QueueRejects <= 0 {
			t.Fatalf("sample %d did not capture bounded queue rejections: %+v", i, sample)
		}
		if sample.StorageBytes <= 0 {
			t.Fatalf("sample %d did not capture datastore/event-log storage: %+v", i, sample)
		}
	}
	report, err := perf.AnalyzeSoak(series.Profile, series.Samples, perf.DefaultSoakThresholds())
	if err != nil {
		t.Fatalf("AnalyzeSoak: %v", err)
	}
	if !report.Summary.OK {
		t.Fatalf("captured series should pass soak gate: %+v", report.Summary)
	}
}

func TestSoakCaptureScriptDoesNotEnableTestSampler(t *testing.T) {
	script, err := os.ReadFile("../../capture-soak-series.sh")
	if err != nil {
		t.Fatalf("read capture script: %v", err)
	}
	if strings.Contains(string(script), "SOAK_CAPTURE_TEST_SAMPLER") {
		t.Fatal("production capture script must not enable SOAK_CAPTURE_TEST_SAMPLER")
	}
	mainSrc, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(mainSrc), "return newLiveSoakSampler()") {
		t.Fatal("soakcapture default path must use the live embedded PostgreSQL/JetStream sampler")
	}
}

func TestConfiguredTestSamplerAndMetricsScrape(t *testing.T) {
	t.Setenv("SOAK_CAPTURE_TEST_SAMPLER", "1")
	sampler, cleanup, err := newConfiguredSoakSampler()
	if err != nil {
		t.Fatalf("newConfiguredSoakSampler: %v", err)
	}
	defer cleanup()
	named, ok := sampler.(perf.SoakMetricSource)
	if !ok || !strings.Contains(named.SoakMetricSource(), "test-harness") {
		source := ""
		if ok {
			source = named.SoakMetricSource()
		}
		t.Fatalf("test sampler source = %T %q", sampler, source)
	}
	snap, err := sampler.CaptureSoakMetrics(7)
	if err != nil {
		t.Fatalf("CaptureSoakMetrics: %v", err)
	}
	if snap.ProjectionLagEvents != 7 || snap.DBPoolSize <= snap.DBPoolInUse || snap.StorageBytes == 0 {
		t.Fatalf("test sampler returned incomplete metrics: %+v", snap)
	}

	reg := observ.NewRegistry()
	reg.Gauge("trstctl_db_pool_in_use", "test").Set(2)
	reg.Gauge("trstctl_db_pool_size", "test").Set(16)
	reg.Gauge("trstctl_bulkhead_rejected_total", "test").Set(1)
	reg.Gauge("trstctl_projection_lag_events", "test").Set(3)
	reg.Gauge("trstctl_outbox_reconciliation_lag_events", "test").Set(4)
	reg.Gauge("trstctl_storage_bytes", "test").Set(1024)
	observ.NewSignerMetrics(reg).Observe(true, 5)
	values, err := scrapeMetrics(reg.Handler())
	if err != nil {
		t.Fatalf("scrapeMetrics: %v", err)
	}
	for _, name := range []string{
		"trstctl_db_pool_in_use",
		"trstctl_db_pool_size",
		"trstctl_bulkhead_rejected_total",
		"trstctl_signer_restarts_total",
		"trstctl_projection_lag_events",
		"trstctl_outbox_reconciliation_lag_events",
		"trstctl_storage_bytes",
	} {
		if _, ok := values[name]; !ok {
			t.Fatalf("scraped metrics missing %s: %#v", name, values)
		}
	}
}

func TestPostgresCandidatePortsValidation(t *testing.T) {
	t.Setenv("SOAK_CAPTURE_POSTGRES_PORT", "25432")
	ports, err := postgresCandidatePorts()
	if err != nil {
		t.Fatalf("postgresCandidatePorts fixed: %v", err)
	}
	if len(ports) != 1 || ports[0] != 25432 {
		t.Fatalf("fixed ports = %#v, want [25432]", ports)
	}

	t.Setenv("SOAK_CAPTURE_POSTGRES_PORT", "70000")
	if _, err := postgresCandidatePorts(); err == nil {
		t.Fatal("postgresCandidatePorts accepted invalid port")
	}
}
