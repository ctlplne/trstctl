// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/perf"
)

func TestSoakGateDirectInputAndReportLifecycle(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "series.json")
	workload := &perf.SoakInputWorkload{Tenants: 2, Agents: 4, EventEquivalent: 20, OutboxEquivalent: 10}
	summary := &perf.SoakInputSummary{OK: true, Samples: 3}
	input := seriesFile{
		Profile: "direct-soak", Source: "embedded-postgres+embedded-jetstream",
		MeasurementArtifact: "series.json", MeasurementMethod: "served capture", CapacityTier: "CAP-SMALL",
		Workload: workload, Summary: summary,
		Samples: perf.SyntheticHealthySeries(3, time.Minute),
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSeries(inputPath)
	if err != nil {
		t.Fatalf("loadSeries: %v", err)
	}
	if loaded.Profile != input.Profile || len(loaded.Samples) != 3 {
		t.Fatalf("loaded series = %+v", loaded)
	}
	evidence := loaded.inputEvidence()
	if evidence == nil || evidence.Source != input.Source || evidence.Workload == nil || evidence.Summary == nil {
		t.Fatalf("input evidence = %+v", evidence)
	}
	if got := (seriesFile{}).inputEvidence(); got != nil {
		t.Fatalf("empty series evidence = %+v", got)
	}

	report, err := perf.AnalyzeSoakWithEvidence(loaded.Profile, loaded.Samples, perf.DefaultSoakThresholds(), evidence)
	if err != nil {
		t.Fatalf("AnalyzeSoakWithEvidence: %v", err)
	}
	outputPath := filepath.Join(dir, "nested", "report.json")
	writeReport(outputPath, false, report)
	output, err := os.ReadFile(outputPath) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var decoded perf.SoakReport
	if err := json.Unmarshal(output, &decoded); err != nil || decoded.Profile != loaded.Profile || decoded.InputEvidence == nil {
		t.Fatalf("written report decode = %+v, %v", decoded, err)
	}

	invalidJSON := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalidJSON, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSeries(invalidJSON); err == nil {
		t.Fatal("loadSeries accepted invalid JSON")
	}
	oneSample := filepath.Join(dir, "one-sample.json")
	data, _ := json.Marshal(seriesFile{Samples: []perf.SoakSample{{T: time.Now().UTC()}}})
	if err := os.WriteFile(oneSample, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSeries(oneSample); err == nil {
		t.Fatal("loadSeries accepted fewer than two samples")
	}
	if _, err := loadSeries(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("loadSeries accepted a missing input")
	}
}

func TestSoakGateCarriesSpineBurstEvidenceIntoTrendReport(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "spine-burst.json")
	outPath := filepath.Join(dir, "soak-report.json")
	series := []byte(`{
  "profile": "spine-burst-cap-small",
  "source": "embedded-postgres+embedded-jetstream+loopback-served-hot-paths",
  "measurement_artifact": "scripts/perf/artifacts/spine-burst-cap-small.json",
  "measurement_method": "embedded PostgreSQL migrations + embedded JetStream appends/replay + bounded outbox drain with slow-upstream backlog, analyzed by scripts/perf/soak.sh",
  "capacity_tier": "CAP-SMALL",
  "workload": {
    "tenants": 5,
    "agents": 50,
    "event_equivalent": 1000,
    "outbox_equivalent": 250,
    "projection_lag_target": 20,
    "outbox_backlog_target": 10,
    "queue_rejects_captured": true,
    "db_pool_captured": true,
    "served_hot_path_artifact": "scripts/perf/artifacts/live-load-baseline.json"
  },
  "slow_upstream": {
    "injected": true,
    "destination": "connector.slow-upstream",
    "delay_ms": 5,
    "bounded_backlog": 10,
    "delivery_pattern": "all fast destinations delivered each sample; slow destination leaves only the bounded target pending"
  },
  "samples": [
    {"t":"2026-06-29T23:56:49Z","rss_bytes":32000000,"heap_bytes":4500000,"goroutines":31,"open_fds":3,"db_pool_in_use":1,"db_pool_size":100,"queue_rejects":0,"signer_restarts":0,"projection_lag_events":20,"outbox_lag_items":10,"storage_bytes":5300000,"p95_ms":5,"p99_ms":6},
    {"t":"2026-06-29T23:57:49Z","rss_bytes":32100000,"heap_bytes":4550000,"goroutines":31,"open_fds":3,"db_pool_in_use":1,"db_pool_size":100,"queue_rejects":0,"signer_restarts":0,"projection_lag_events":20,"outbox_lag_items":10,"storage_bytes":5400000,"p95_ms":5,"p99_ms":6}
  ],
  "summary": {
    "ok": true,
    "samples": 2,
    "appended_events": 1002,
    "replayed_events": 3387,
    "projection_lag_events": 20,
    "outbox_queued": 252,
    "outbox_pending": 10,
    "queue_rejects": 0,
    "soak_summary": {"metrics": 18, "breached": 0, "ok": true}
  }
}`)
	if err := os.WriteFile(inPath, series, 0o600); err != nil {
		t.Fatalf("write input series: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "--in", inPath, "--out", outPath, "--profile", "spine-burst-cap-small", "--pretty=false") // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(dir, "gocache"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("soakgate failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read output report: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode output report: %v\n%s", err, data)
	}
	evidence, ok := report["input_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("soak trend report missing input_evidence: %s", data)
	}
	if source, _ := evidence["source"].(string); !strings.Contains(source, "embedded-postgres") || !strings.Contains(source, "embedded-jetstream") {
		t.Fatalf("input_evidence.source = %q, want embedded datastore evidence", source)
	}
	if artifact, _ := evidence["measurement_artifact"].(string); artifact != "scripts/perf/artifacts/spine-burst-cap-small.json" {
		t.Fatalf("input_evidence.measurement_artifact = %q", artifact)
	}
	workload, ok := evidence["workload"].(map[string]any)
	if !ok {
		t.Fatalf("input_evidence missing workload: %+v", evidence)
	}
	if workload["event_equivalent"] != float64(1000) || workload["outbox_equivalent"] != float64(250) {
		t.Fatalf("input_evidence workload lost burst scale: %+v", workload)
	}
	summary, ok := evidence["summary"].(map[string]any)
	if !ok {
		t.Fatalf("input_evidence missing summary: %+v", evidence)
	}
	if summary["appended_events"] != float64(1002) || summary["outbox_pending"] != float64(10) {
		t.Fatalf("input_evidence summary lost replay/outbox receipt: %+v", summary)
	}
}
