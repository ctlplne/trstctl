package perf

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func BenchmarkIssuance(b *testing.B) {
	benchmarkOperation(b, "api.issuance")
}

func BenchmarkInventory(b *testing.B) {
	benchmarkOperation(b, "api.inventory")
}

func BenchmarkGraphRiskQuery(b *testing.B) {
	benchmarkOperation(b, "api.graph_risk")
}

func BenchmarkSecrets(b *testing.B) {
	benchmarkOperation(b, "api.secrets")
}

func BenchmarkProtocolEnrollment(b *testing.B) {
	benchmarkOperation(b, "protocol.enrollment")
}

func BenchmarkOCSPCRL(b *testing.B) {
	benchmarkOperation(b, "revocation.ocsp_crl")
}

func BenchmarkSignerRPC(b *testing.B) {
	benchmarkOperation(b, "signer.rpc")
}

func BenchmarkProjectionReplay(b *testing.B) {
	benchmarkOperation(b, "spine.projection_replay")
}

func TestPerfSmokeGateCoversEveryHotPath(t *testing.T) {
	report, err := RunSmoke("smoke", 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != len(HotPaths()) {
		t.Fatalf("smoke results = %d, want %d", len(report.Results), len(HotPaths()))
	}
	for _, result := range report.Results {
		if !result.Met {
			t.Fatalf("%s failed smoke SLO: %+v", result.HotPath, result)
		}
	}
}

func TestPerfSmokeGateFailsInjectedRuntimeBreaches(t *testing.T) {
	report, err := RunSmokeWithObservations("smoke", 8, map[string]Observation{
		"api.issuance":            {QueueSaturation: 0.81},
		"api.inventory":           {ErrorBudgetPercent: 0.11},
		"spine.projection_replay": {ProjectionLagEvents: 51},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.OK {
		t.Fatalf("smoke report unexpectedly passed with injected queue/error/lag breaches: %+v", report.Summary)
	}
	want := map[string]string{
		"api.issuance":            "queue saturation",
		"api.inventory":           "error budget",
		"spine.projection_replay": "projection lag",
	}
	for _, result := range report.Results {
		substr, ok := want[result.HotPath]
		if !ok {
			continue
		}
		if result.Met {
			t.Fatalf("%s met SLO despite injected %q breach: %+v", result.HotPath, substr, result)
		}
		if !containsFailure(result.Failures, substr) {
			t.Fatalf("%s failures = %v, want %q", result.HotPath, result.Failures, substr)
		}
		delete(want, result.HotPath)
	}
	if len(want) != 0 {
		t.Fatalf("missing injected breach results for %v", want)
	}
}

func TestPerfSmokeGateRejectsUnknownObservationHotPath(t *testing.T) {
	_, err := RunSmokeWithObservations("smoke", 1, map[string]Observation{
		"not.a.hot.path": {QueueSaturation: 1},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown hot path") {
		t.Fatalf("RunSmokeWithObservations error = %v, want unknown hot path", err)
	}
}

func TestPerfLiveLoadHarnessCoversEveryHotPathAndPhase(t *testing.T) {
	report, err := RunLiveLoad("live", 16)
	if err != nil {
		t.Fatal(err)
	}
	if report.Profile != "live" {
		t.Fatalf("profile = %q, want live", report.Profile)
	}
	if report.MeasurementArtifact != LiveMeasurementArtifact {
		t.Fatalf("measurement artifact = %q, want %q", report.MeasurementArtifact, LiveMeasurementArtifact)
	}
	if !report.ServedStack {
		t.Fatal("live report did not mark the served stack as booted")
	}
	if report.StackProfile == "" {
		t.Fatal("live report has no stack profile")
	}
	if len(report.LoadPhases) != 2 {
		t.Fatalf("live phases = %d, want realistic and peak", len(report.LoadPhases))
	}
	if got, want := len(report.Results), len(HotPaths())*len(report.LoadPhases); got != want {
		t.Fatalf("live results = %d, want %d", got, want)
	}

	seen := map[string]bool{}
	for _, result := range report.Results {
		if !result.ServedStack {
			t.Fatalf("%s/%s did not mark served_stack", result.HotPath, result.Phase)
		}
		if result.StackProfile != report.StackProfile {
			t.Fatalf("%s/%s stack profile = %q, want %q", result.HotPath, result.Phase, result.StackProfile, report.StackProfile)
		}
		if result.Phase != "realistic" && result.Phase != "peak" {
			t.Fatalf("%s phase = %q, want realistic or peak", result.HotPath, result.Phase)
		}
		if result.P50MS <= 0 || result.P95MS <= 0 || result.P99MS <= 0 || result.MaxMS <= 0 {
			t.Fatalf("%s/%s missing latency percentiles/max: %+v", result.HotPath, result.Phase, result)
		}
		if result.MaxMS < result.P99MS {
			t.Fatalf("%s/%s max %.4fms < p99 %.4fms", result.HotPath, result.Phase, result.MaxMS, result.P99MS)
		}
		if result.ThroughputPerSecond <= 0 || result.TargetRatePerSecond <= 0 {
			t.Fatalf("%s/%s missing throughput/target rate: %+v", result.HotPath, result.Phase, result)
		}
		if result.Errors != 0 {
			t.Fatalf("%s/%s recorded %d errors: %+v", result.HotPath, result.Phase, result.Errors, result.Failures)
		}
		if result.ResourceMetrics == nil || result.ResourceMetrics.Goroutines <= 0 || result.ResourceMetrics.CPUCount <= 0 {
			t.Fatalf("%s/%s missing resource metrics: %+v", result.HotPath, result.Phase, result.ResourceMetrics)
		}
		seen[result.HotPath+"/"+result.Phase] = true
	}
	for _, slo := range HotPaths() {
		for _, phase := range []string{"realistic", "peak"} {
			key := slo.HotPath + "/" + phase
			if !seen[key] {
				t.Fatalf("missing live result for %s", key)
			}
		}
	}
	if report.Summary.Measurements != len(report.Results) || report.Summary.HotPaths != len(HotPaths()) {
		t.Fatalf("bad live summary: %+v", report.Summary)
	}
}

func TestPerfLiveLoadNamesProductionServedRoutes(t *testing.T) {
	report, err := RunLiveLoad("live", 4)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"api.issuance":            "POST /api/v1/identities",
		"api.inventory":           "GET /api/v1/certificates",
		"api.graph_risk":          "GET /api/v1/graph",
		"api.secrets":             "PUT /api/v1/secrets",
		"protocol.enrollment":     "POST /.well-known/acme",
		"revocation.ocsp_crl":     "POST /ocsp/{tenant}",
		"signer.rpc":              "gRPC trstctl.signing.SignerService",
		"spine.projection_replay": "events replay -> projections.Apply",
	}
	for _, result := range report.Results {
		route, ok := want[result.HotPath]
		if !ok {
			t.Fatalf("unexpected live hot path %q", result.HotPath)
		}
		if !strings.Contains(result.Transport, "served-route: "+route) {
			t.Fatalf("%s/%s transport = %q, want production served route %q", result.HotPath, result.Phase, result.Transport, route)
		}
		if strings.Contains(result.Transport, "/perf/live/") || strings.Contains(result.Transport, "library-only") {
			t.Fatalf("%s/%s transport still reports non-production coverage: %q", result.HotPath, result.Phase, result.Transport)
		}
	}
}

func TestPerfLiveLoadGateFailsInjectedRuntimeBreaches(t *testing.T) {
	report, err := RunLiveLoadWithObservations("live", 16, map[string]Observation{
		"api.issuance": {QueueSaturation: 0.81},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.OK {
		t.Fatalf("live report unexpectedly passed with injected queue breach: %+v", report.Summary)
	}
	found := false
	for _, result := range report.Results {
		if result.HotPath != "api.issuance" {
			continue
		}
		found = true
		if result.Met {
			t.Fatalf("api.issuance/%s met SLO despite injected queue breach: %+v", result.Phase, result)
		}
		if !containsFailure(result.Failures, "queue saturation") {
			t.Fatalf("api.issuance/%s failures = %v, want queue saturation", result.Phase, result.Failures)
		}
	}
	if !found {
		t.Fatal("missing api.issuance live result")
	}
}

func TestScaleOrchestrationPlanCoversHundredKToMillionCredentials(t *testing.T) {
	plan := ScaleOrchestration("2026-06-29T00:00:00Z")
	if plan.Capability != "CAP-SCALE-01" || !plan.Served {
		t.Fatalf("capability/served = %q/%v, want CAP-SCALE-01/true", plan.Capability, plan.Served)
	}
	if plan.SelectedCapacityTier.ID != "CAP-LARGE" || plan.SelectedCapacityTier.ManagedCredentials < 1_000_000 {
		t.Fatalf("selected tier = %+v, want CAP-LARGE for 1M+ credentials", plan.SelectedCapacityTier)
	}
	if len(plan.HotPathSLOs) != len(HotPaths()) {
		t.Fatalf("hot path SLOs = %d, want %d", len(plan.HotPathSLOs), len(HotPaths()))
	}
	for _, want := range []string{"SCALE-100K", "SCALE-1M"} {
		found := false
		for _, band := range plan.TargetCredentialBands {
			found = found || band.ID == want
		}
		if !found {
			t.Fatalf("missing credential band %s in %+v", want, plan.TargetCredentialBands)
		}
	}
	for _, want := range []string{"scale-issue", "scale-signer", "scale-projections"} {
		found := false
		for _, lane := range plan.ExecutionLanes {
			if lane.ID != want {
				continue
			}
			found = true
			if len(lane.BulkheadEnv) == 0 || lane.BackpressureSignal == "" || lane.HotPathSLO == "" {
				t.Fatalf("lane %s missing bulkhead/backpressure/SLO evidence: %+v", want, lane)
			}
		}
		if !found {
			t.Fatalf("missing execution lane %s", want)
		}
	}
	for _, want := range []string{MeasurementArtifact, LiveMeasurementArtifact, CapacityMeasurementArtifact, SpineBurstArtifact} {
		found := false
		for _, artifact := range plan.MeasurementArtifacts {
			found = found || artifact == want
		}
		if !found {
			t.Fatalf("missing measurement artifact %s in %+v", want, plan.MeasurementArtifacts)
		}
	}
}

func TestCapacityMeasurementArtifactDerivesServedCapacityTiers(t *testing.T) {
	data, err := os.ReadFile("../../" + CapacityMeasurementArtifact)
	if err != nil {
		t.Fatalf("read %s: %v", CapacityMeasurementArtifact, err)
	}
	var report CapacityMeasurementReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse %s: %v", CapacityMeasurementArtifact, err)
	}
	if report.MeasurementArtifact != CapacityMeasurementArtifact || !report.Summary.OK {
		t.Fatalf("capacity artifact identity/summary = %q/%+v, want %q and ok", report.MeasurementArtifact, report.Summary, CapacityMeasurementArtifact)
	}
	if report.SampleSize < 1000 {
		t.Fatalf("capacity sample size = %d, want at least 1000", report.SampleSize)
	}
	requiredUnits := map[string]bool{
		"postgres_certificate_row": false,
		"postgres_credential_row":  false,
		"jetstream_event":          false,
		"audit_record_json":        false,
	}
	for _, measurement := range report.StorageMeasurements {
		if measurement.BytesPerUnit <= 0 || measurement.Samples <= 0 || measurement.MeasurementSource == "" {
			t.Fatalf("incomplete storage measurement: %+v", measurement)
		}
		if _, ok := requiredUnits[measurement.ID]; ok {
			requiredUnits[measurement.ID] = true
		}
	}
	for id, seen := range requiredUnits {
		if !seen {
			t.Fatalf("capacity artifact missing measured unit %s", id)
		}
	}
	if report.ResourceMeasurement.CPUCount <= 0 ||
		report.ResourceMeasurement.PeakMemorySysBytes == 0 ||
		report.ResourceMeasurement.PostgresCalibrationConnections <= 0 ||
		report.ResourceMeasurement.SignerRPCPeakThroughputPerSecond <= 0 {
		t.Fatalf("capacity artifact missing live resource/signer/connection counters: %+v", report.ResourceMeasurement)
	}
	if got := DeriveCapacityTiers(report); !reflect.DeepEqual(got, report.DerivedCapacityTiers) {
		t.Fatalf("artifact tiers no longer derive from measured artifact:\n got=%+v\nwant=%+v", got, report.DerivedCapacityTiers)
	}
	if !reflect.DeepEqual(CapacityTiers(), report.DerivedCapacityTiers) {
		t.Fatalf("served capacity tiers no longer match measured artifact:\n got=%+v\nwant=%+v", CapacityTiers(), report.DerivedCapacityTiers)
	}
}

func TestSpineBurstArtifactPassesSoakThresholds(t *testing.T) {
	data, err := os.ReadFile("../../" + SpineBurstArtifact)
	if err != nil {
		t.Fatalf("read %s: %v", SpineBurstArtifact, err)
	}
	var artifact struct {
		Profile             string `json:"profile"`
		Source              string `json:"source"`
		MeasurementArtifact string `json:"measurement_artifact"`
		Workload            struct {
			Tenants              int  `json:"tenants"`
			Agents               int  `json:"agents"`
			EventEquivalent      int  `json:"event_equivalent"`
			OutboxEquivalent     int  `json:"outbox_equivalent"`
			QueueRejectsCaptured bool `json:"queue_rejects_captured"`
			DBPoolCaptured       bool `json:"db_pool_captured"`
		} `json:"workload"`
		SlowUpstream struct {
			Injected bool `json:"injected"`
		} `json:"slow_upstream"`
		Samples []SoakSample `json:"samples"`
		Summary struct {
			OK             bool `json:"ok"`
			AppendedEvents int  `json:"appended_events"`
			OutboxQueued   int  `json:"outbox_queued"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatalf("parse %s: %v", SpineBurstArtifact, err)
	}
	if artifact.MeasurementArtifact != SpineBurstArtifact || !artifact.Summary.OK {
		t.Fatalf("spine burst artifact identity/summary = %q/%+v, want %q and ok", artifact.MeasurementArtifact, artifact.Summary, SpineBurstArtifact)
	}
	if !strings.Contains(artifact.Source, "embedded-postgres") || !strings.Contains(artifact.Source, "embedded-jetstream") {
		t.Fatalf("spine burst source = %q, want embedded datastore evidence", artifact.Source)
	}
	if artifact.Workload.Tenants < 5 || artifact.Workload.Agents < 50 || artifact.Summary.AppendedEvents < 1000 || artifact.Summary.OutboxQueued < 250 {
		t.Fatalf("spine burst workload too small: workload=%+v summary=%+v", artifact.Workload, artifact.Summary)
	}
	if !artifact.Workload.QueueRejectsCaptured || !artifact.Workload.DBPoolCaptured || !artifact.SlowUpstream.Injected {
		t.Fatalf("spine burst artifact missing queue/db/slow-upstream evidence: workload=%+v slow=%+v", artifact.Workload, artifact.SlowUpstream)
	}
	report, err := AnalyzeSoak(artifact.Profile, artifact.Samples, DefaultSoakThresholds())
	if err != nil {
		t.Fatalf("analyze %s: %v", SpineBurstArtifact, err)
	}
	if !report.Summary.OK {
		t.Fatalf("spine burst artifact no longer passes soak thresholds: %+v", report.Summary)
	}
}

func TestActiveActiveIssuancePlanServesFencedRegionalIssuance(t *testing.T) {
	plan := ActiveActiveIssuance("2026-06-29T00:00:00Z")
	if plan.Capability != "CAP-SCALE-02" || !plan.Served {
		t.Fatalf("capability/served = %q/%v, want CAP-SCALE-02/true", plan.Capability, plan.Served)
	}
	if len(plan.Regions) < 2 {
		t.Fatalf("regions = %d, want at least two active ingress regions", len(plan.Regions))
	}
	if plan.RPOSeconds <= 0 || plan.RTOSeconds <= 0 {
		t.Fatalf("RPO/RTO = %d/%d, want positive targets", plan.RPOSeconds, plan.RTOSeconds)
	}
	for _, want := range []string{"idempotency", "event-log", "outbox", "leader-workers", "signer-boundary"} {
		found := false
		for _, fence := range plan.TenantWriteFences {
			if fence.ID != want {
				continue
			}
			found = true
			if fence.Mechanism == "" || fence.ConflictOutcome == "" || fence.Evidence == "" {
				t.Fatalf("fence %s missing mechanism/outcome/evidence: %+v", want, fence)
			}
		}
		if !found {
			t.Fatalf("missing write fence %s", want)
		}
	}
	for _, lane := range plan.IssuanceLanes {
		if lane.MutationFence == "" || lane.EventAppend == "" || lane.OutboxMode == "" || lane.SignerMode == "" {
			t.Fatalf("lane missing issuance fences: %+v", lane)
		}
	}
	for _, want := range []string{"regional-smoke", "failover-drill", "architecture-lint"} {
		found := false
		for _, gate := range plan.ReleaseGates {
			found = found || gate.ID == want && gate.Required
		}
		if !found {
			t.Fatalf("missing required release gate %s", want)
		}
	}
	for _, want := range []string{"AN-2", "AN-4", "AN-5", "AN-6", "AN-7"} {
		found := false
		for _, invariant := range plan.ArchitectureInvariants {
			found = found || invariant == want
		}
		if !found {
			t.Fatalf("missing invariant %s in %+v", want, plan.ArchitectureInvariants)
		}
	}
}

func containsFailure(failures []string, substr string) bool {
	for _, failure := range failures {
		if strings.Contains(failure, substr) {
			return true
		}
	}
	return false
}

func benchmarkOperation(b *testing.B, hotPath string) {
	ops, cleanup, err := operations()
	if err != nil {
		b.Fatal(err)
	}
	defer cleanup()
	op, ok := ops[hotPath]
	if !ok {
		b.Fatalf("no perf operation for %s", hotPath)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := op(); err != nil {
			b.Fatal(err)
		}
	}
}
