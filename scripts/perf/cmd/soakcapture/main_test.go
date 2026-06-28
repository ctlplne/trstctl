package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/perf"
)

func TestSoakCaptureCommandWritesAnalyzerInput(t *testing.T) {
	dir := t.TempDir()
	seriesPath := filepath.Join(dir, "series.json")
	cmd := exec.Command("go", "run", ".", "--samples", "3", "--step-seconds", "60", "--load-samples", "4", "--no-sleep", "--pretty=false", "--out", seriesPath)
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(dir, "gocache"))
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
	report, err := perf.AnalyzeSoak(series.Profile, series.Samples, perf.DefaultSoakThresholds())
	if err != nil {
		t.Fatalf("AnalyzeSoak: %v", err)
	}
	if !report.Summary.OK {
		t.Fatalf("captured series should pass soak gate: %+v", report.Summary)
	}
}
