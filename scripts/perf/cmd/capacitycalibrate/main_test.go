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

func TestServedLiveArtifactValidationAndCapacityHelpers(t *testing.T) {
	report := validServedLiveReport()
	if err := validateServedLiveArtifact(report); err != nil {
		t.Fatalf("validateServedLiveArtifact valid report: %v", err)
	}
	report.Results[0].Transport = "library-only"
	if err := validateServedLiveArtifact(report); err == nil || !strings.Contains(err.Error(), "non-served transport") {
		t.Fatalf("library-only transport error = %v, want non-served transport", err)
	}
	report = validServedLiveReport()
	report.Results[0].Transport = "served-route: POST /api/v1/identities via httptest product mux"
	if err := validateServedLiveArtifact(report); err == nil || !strings.Contains(err.Error(), "non-served transport") {
		t.Fatalf("httptest transport error = %v, want non-served transport", err)
	}
	report = validServedLiveReport()
	report.Results[0].Transport = "served-route: gRPC trstctl.signing.SignerService/Sign over bufconn-grpc-signer"
	if err := validateServedLiveArtifact(report); err == nil || !strings.Contains(err.Error(), "non-served transport") {
		t.Fatalf("bufconn transport error = %v, want non-served transport", err)
	}

	payload, err := representativeEventPayload(7)
	if err != nil {
		t.Fatalf("representativeEventPayload: %v", err)
	}
	if !json.Valid(payload) || !strings.Contains(string(payload), "svc-00007.capacity.trstctl.test") {
		t.Fatalf("representative payload invalid: %s", payload)
	}
	if uuidFromInt(42) != "00000000-0000-4000-8000-00000000002a" {
		t.Fatalf("uuidFromInt unexpected")
	}
	if ceilDiv(0, 9) != 0 || ceilDiv(10, 3) != 4 {
		t.Fatalf("ceilDiv unexpected")
	}
	data, err := marshal(map[string]any{"ok": true}, false)
	if err != nil || !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("marshal = %q, %v", data, err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "b.txt"), []byte("de"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := dirSize(root); err != nil || got != 5 {
		t.Fatalf("dirSize = %d, %v; want 5", got, err)
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

func validServedLiveReport() perf.Report {
	results := make([]perf.Result, 0, len(perf.HotPaths())*2)
	for _, slo := range perf.HotPaths() {
		for _, phase := range []string{"realistic", "peak"} {
			results = append(results, perf.Result{
				HotPath:             slo.HotPath,
				Phase:               phase,
				ServedStack:         true,
				StackProfile:        requiredLiveStackProfile,
				Transport:           "served-route:/api/v1/perf/" + strings.ReplaceAll(slo.HotPath, ".", "/"),
				ThroughputPerSecond: 1000,
				ResourceMetrics:     resourceMetrics(),
				Met:                 true,
			})
		}
	}
	return perf.Report{
		SchemaVersion:       1,
		Profile:             "live",
		MeasurementArtifact: perf.LiveMeasurementArtifact,
		ServedStack:         true,
		StackProfile:        requiredLiveStackProfile,
		ResourceMetrics:     resourceMetrics(),
		Results:             results,
		Summary:             perf.Summary{OK: true},
	}
}
