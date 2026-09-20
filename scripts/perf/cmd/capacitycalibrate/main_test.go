// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/perf"
)

func TestCapacityCalibrationMeasuresEmbeddedStorage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const samples = 4
	pg, err := measurePostgres(ctx, samples)
	if err != nil {
		t.Fatalf("measurePostgres against embedded PostgreSQL: %v", err)
	}
	if pg.connections <= 0 || pg.certificateBytesTotal <= 0 || pg.certificateBytesPerRow <= 0 || pg.credentialBytesTotal <= 0 || pg.credentialBytesPerRow <= 0 {
		t.Fatalf("incomplete PostgreSQL measurement: %+v", pg)
	}
	if pg.certificateBytesPerRow != ceilDiv(pg.certificateBytesTotal, samples) || pg.credentialBytesPerRow != ceilDiv(pg.credentialBytesTotal, samples) {
		t.Fatalf("per-row storage does not match measured totals: %+v", pg)
	}

	jetstream, err := measureJetStream(ctx, samples)
	if err != nil {
		t.Fatalf("measureJetStream against embedded file-backed JetStream: %v", err)
	}
	if jetstream.bytesTotal <= 0 || jetstream.bytesPerEvent <= 0 {
		t.Fatalf("incomplete JetStream measurement: %+v", jetstream)
	}
	if jetstream.bytesPerEvent != ceilDiv(jetstream.bytesTotal, samples) {
		t.Fatalf("per-event storage does not match measured total: %+v", jetstream)
	}

	auditBytes, err := measureAuditRecordBytes()
	if err != nil {
		t.Fatalf("measureAuditRecordBytes: %v", err)
	}
	if auditBytes <= 0 {
		t.Fatalf("audit projection serialized size = %d, want positive", auditBytes)
	}
}

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
	if len(got.ComponentResources) != len(fullProductResourceMetrics()) {
		t.Fatalf("component resource measurements = %d, want %d", len(got.ComponentResources), len(fullProductResourceMetrics()))
	}
}

func TestMeasureResourcesRejectsServedLiveArtifactWithoutFullProductCounters(t *testing.T) {
	report := validServedLiveReport()
	report.ComponentResources = nil
	path := writeLiveArtifact(t, report)

	_, err := measureResources(path, 1)
	if err == nil {
		t.Fatal("measureResources accepted a served live-load artifact without full-product component counters")
	}
	if !strings.Contains(err.Error(), "component resource counters") {
		t.Fatalf("measureResources error = %v, want component resource counters rejection", err)
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
	report = validServedLiveReport()
	report.ComponentResources = fullProductResourceMetrics()
	report.ComponentResources[1].PID = report.ComponentResources[0].PID
	if err := validateServedLiveArtifact(report); err == nil || !strings.Contains(err.Error(), "control-plane process pid") {
		t.Fatalf("shared signer pid error = %v, want separate process rejection", err)
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
	if err := os.WriteFile(path, data, 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
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
		RSSBytes:       8192,
		VirtualBytes:   16384,
	}
}

func fullProductResourceMetrics() []perf.ComponentResourceMetrics {
	return []perf.ComponentResourceMetrics{
		{Component: "control_plane", Kind: "process", PID: 101, Runtime: "trstctl-control-plane", Metrics: resourceMetrics()},
		{Component: "signer", Kind: "process", PID: 202, Runtime: "trstctl-signer-child-process", Metrics: resourceMetrics()},
		{Component: "postgresql", Kind: "process", PID: 303, Runtime: "embedded-postgres-backend-process", Metrics: resourceMetrics()},
		{Component: "jetstream", Kind: "process", PID: 101, Runtime: "embedded-jetstream-in-control-plane-process", Metrics: resourceMetrics()},
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
		ComponentResources:  fullProductResourceMetrics(),
		Results:             results,
		Summary:             perf.Summary{OK: true},
	}
}
