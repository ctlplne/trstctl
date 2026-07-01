package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/perf"
)

func TestMeasureResourcesRejectsSyntheticLiveArtifact(t *testing.T) {
	path := writeLiveArtifact(t, perf.Report{
		SchemaVersion:       1,
		Profile:             "live",
		MeasurementArtifact: perf.LiveMeasurementArtifact,
		ServedStack:         false,
		StackProfile:        "synthetic-selftest",
		ResourceMetrics:     resourceMetrics(),
		Results: []perf.Result{
			liveResult("api.issuance", "realistic", "http-handler", 1000),
			liveResult("signer.rpc", "peak", "http-handler+bufconn-grpc-signer", 1200),
			liveResult("spine.projection_replay", "peak", "http-handler", 2000),
		},
		Summary: perf.Summary{OK: true},
	})

	_, err := measureResources(path, 1)
	if err == nil {
		t.Fatal("measureResources accepted a synthetic live-load artifact")
	}
	if !strings.Contains(err.Error(), "served live-load") {
		t.Fatalf("measureResources error = %v, want served live-load rejection", err)
	}
}

func TestMeasureResourcesImportsServedLiveArtifact(t *testing.T) {
	path := filepath.Join("..", "..", "artifacts", "live-load-baseline.json")

	got, err := measureResources(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.LiveStackProfile != requiredLiveStackProfile {
		t.Fatalf("live stack profile = %q, want %q", got.LiveStackProfile, requiredLiveStackProfile)
	}
	if got.PostgresCalibrationConnections != 2 {
		t.Fatalf("postgres calibration connections = %d, want 2", got.PostgresCalibrationConnections)
	}
	if got.CPUCount <= 0 || got.PeakMemorySysBytes == 0 || got.SignerRPCPeakThroughputPerSecond <= 0 || got.ProjectionReplayThroughputPerSecond <= 0 {
		t.Fatalf("incomplete resource measurement: %+v", got)
	}
}

func writeLiveArtifact(t *testing.T, report perf.Report) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "live.json")
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func liveResult(hotPath, phase, transport string, throughput float64) perf.Result {
	return perf.Result{
		HotPath:             hotPath,
		Phase:               phase,
		ServedStack:         true,
		StackProfile:        "synthetic-selftest",
		Transport:           transport,
		ThroughputPerSecond: throughput,
		ResourceMetrics:     resourceMetrics(),
		Met:                 true,
	}
}

func resourceMetrics() *perf.ResourceMetrics {
	return &perf.ResourceMetrics{
		Goroutines:     8,
		CPUCount:       4,
		OpenFDs:        8,
		HeapInuseBytes: 4096,
		MemorySysBytes: 8192,
	}
}
