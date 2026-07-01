package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
