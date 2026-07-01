package docs

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/perf"
)

func TestPerformanceSLOMatrixHasExecutableEvidence(t *testing.T) {
	doc := read(t, "performance.md")
	artifact := readPerfArtifact(t)
	results := map[string]perf.Result{}
	for _, result := range artifact.Results {
		results[result.HotPath] = result
		if !result.Met {
			t.Errorf("perf artifact marks %s as not met: %+v", result.HotPath, result)
		}
	}
	if !artifact.Summary.OK {
		t.Fatalf("perf artifact summary is not ok: %+v", artifact.Summary)
	}
	for _, slo := range perf.HotPaths() {
		for _, want := range []string{slo.ID, slo.HotPath, slo.Benchmark, slo.Owner, slo.CapacityRef} {
			if !strings.Contains(doc, want) {
				t.Errorf("performance.md missing %q for %s", want, slo.ID)
			}
		}
		result, ok := results[slo.HotPath]
		if !ok {
			t.Errorf("perf artifact missing hot path %s", slo.HotPath)
			continue
		}
		if result.SLOID != slo.ID {
			t.Errorf("%s artifact SLO id = %s, want %s", slo.HotPath, result.SLOID, slo.ID)
		}
		if result.Benchmark != slo.Benchmark {
			t.Errorf("%s artifact benchmark = %s, want %s", slo.HotPath, result.Benchmark, slo.Benchmark)
		}
		if result.P50MS > slo.P50MS || result.P95MS > slo.P95MS || result.P99MS > slo.P99MS {
			t.Errorf("%s latency p50/p95/p99 = %.3f/%.3f/%.3f exceeds %.3f/%.3f/%.3f",
				slo.HotPath, result.P50MS, result.P95MS, result.P99MS, slo.P50MS, slo.P95MS, slo.P99MS)
		}
		if result.ThroughputPerSecond < slo.MinThroughputPerSecond {
			t.Errorf("%s throughput = %.2f, want >= %.2f", slo.HotPath, result.ThroughputPerSecond, slo.MinThroughputPerSecond)
		}
	}
}

func TestPerformanceCapacityModelIsTiedToPerfArtifact(t *testing.T) {
	doc := read(t, "performance-capacity.md")
	for _, want := range []string{perf.MeasurementArtifact, perf.LiveMeasurementArtifact, perf.CapacityMeasurementArtifact, perf.SpineBurstArtifact, "scripts/perf/run-capacity-calibration.sh", "scripts/perf/run-spine-burst.sh"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("performance-capacity.md must cite %s", want)
		}
	}
	artifact := readPerfArtifact(t)
	artifactTiers := map[string]bool{}
	for _, tier := range artifact.CapacityTiers {
		artifactTiers[tier] = true
	}
	capacityArtifact := readCapacityMeasurementArtifact(t)
	if capacityArtifact.MeasurementArtifact != perf.CapacityMeasurementArtifact {
		t.Fatalf("capacity artifact names %q, want %q", capacityArtifact.MeasurementArtifact, perf.CapacityMeasurementArtifact)
	}
	if !capacityArtifact.Summary.OK {
		t.Fatalf("capacity artifact summary is not ok: %+v", capacityArtifact.Summary)
	}
	if got := perf.DeriveCapacityTiers(capacityArtifact); !reflect.DeepEqual(got, capacityArtifact.DerivedCapacityTiers) {
		t.Fatalf("capacity artifact derived tiers no longer match perf.DeriveCapacityTiers:\n got=%+v\nwant=%+v", got, capacityArtifact.DerivedCapacityTiers)
	}
	capacityTiers := map[string]perf.CapacityTier{}
	for _, tier := range capacityArtifact.DerivedCapacityTiers {
		capacityTiers[tier.ID] = tier
	}
	for _, tier := range perf.CapacityTiers() {
		measured, ok := capacityTiers[tier.ID]
		if !ok {
			t.Fatalf("capacity artifact missing derived tier %s", tier.ID)
		}
		if !reflect.DeepEqual(tier, measured) {
			t.Fatalf("served tier %s no longer matches measured capacity artifact:\n got=%+v\nwant=%+v", tier.ID, tier, measured)
		}
		for _, want := range []string{
			tier.ID,
			tier.Name,
			formatInt(tier.ManagedCredentials),
			formatGiB(tier.PostgresGiB30Day) + " GiB",
			formatGiB(tier.JetStreamGiB30Day) + " GiB",
			formatUSD(tier.EstimatedMonthlyCostUSD),
			fmt.Sprintf("$%.4f", tier.EstimatedCostPerCredential),
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("performance-capacity.md missing %q for %s", want, tier.ID)
			}
		}
		if !artifactTiers[tier.ID] {
			t.Errorf("perf artifact missing capacity tier %s", tier.ID)
		}
	}
	for _, measurement := range capacityArtifact.StorageMeasurements {
		if measurement.ID == "" || measurement.BytesPerUnit <= 0 || measurement.Samples <= 0 {
			t.Fatalf("capacity artifact has incomplete storage measurement: %+v", measurement)
		}
		if !strings.Contains(doc, measurement.ID) && !strings.Contains(doc, measurement.MeasurementSource) && !strings.Contains(doc, measurement.Unit) {
			t.Errorf("performance-capacity.md missing measured unit evidence for %s", measurement.ID)
		}
	}
}

func TestSpineBurstGateIsExecutableEvidence(t *testing.T) {
	perfDoc := read(t, "performance.md")
	capacityDoc := read(t, "performance-capacity.md")
	for _, want := range []string{
		"make spine-burst",
		"scripts/perf/run-spine-burst.sh --profile cap-small",
		"scripts/perf/soak.sh --in scripts/perf/artifacts/spine-burst-cap-small.json",
		perf.SpineBurstArtifact,
		"embedded PostgreSQL",
		"embedded JetStream",
		"projection lag",
		"outbox backlog",
		"DB-pool utilization",
	} {
		if !strings.Contains(perfDoc, want) && !strings.Contains(capacityDoc, want) {
			t.Errorf("perf docs missing spine-burst evidence %q", want)
		}
	}
	mk := read(t, "../Makefile")
	for _, want := range []string{"spine-burst:", "scripts/perf/run-spine-burst.sh --profile cap-small", "scripts/perf/soak.sh --in"} {
		if !strings.Contains(mk, want) {
			t.Errorf("Makefile missing spine-burst gate evidence %q", want)
		}
	}
	script := read(t, "../scripts/perf/run-spine-burst.sh")
	for _, want := range []string{"./scripts/perf/cmd/spineburst", "--outbox-items", "--slow-upstream-ms"} {
		if !strings.Contains(script, want) {
			t.Errorf("run-spine-burst.sh missing argument or command evidence %q", want)
		}
	}
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{"spine burst / replay-outbox gate", "scripts/perf/run-spine-burst.sh --profile cap-small", "spine-burst-trend"} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml missing spine-burst scheduled gate evidence %q", want)
		}
	}
	artifact := readSpineBurstArtifact(t)
	if !artifact.Summary.OK || artifact.MeasurementArtifact != perf.SpineBurstArtifact {
		t.Fatalf("spine burst artifact identity/summary = %q/%+v, want %q and ok", artifact.MeasurementArtifact, artifact.Summary, perf.SpineBurstArtifact)
	}
	if len(artifact.Samples) < 2 || artifact.Workload.EventEquivalent < 1000 || artifact.Workload.OutboxEquivalent < 250 {
		t.Fatalf("spine burst artifact too small: samples=%d workload=%+v", len(artifact.Samples), artifact.Workload)
	}
	report, err := perf.AnalyzeSoak(artifact.Profile, artifact.Samples, perf.DefaultSoakThresholds())
	if err != nil {
		t.Fatalf("analyze spine burst artifact: %v", err)
	}
	if !report.Summary.OK {
		t.Fatalf("spine burst artifact no longer passes soak thresholds: %+v", report.Summary)
	}
}

func TestPerfSmokeScriptAndCIArtifactGateAreCommitted(t *testing.T) {
	script, err := os.ReadFile("../scripts/perf/run-local.sh")
	if err != nil {
		t.Fatalf("read perf script: %v", err)
	}
	for _, want := range []string{"--profile", "--out", "smoke|live", "./scripts/perf/cmd/perfgate"} {
		if !strings.Contains(string(script), want) {
			t.Errorf("scripts/perf/run-local.sh missing %q", want)
		}
	}
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{"Perf smoke SLO gate", "scripts/perf/run-local.sh --profile smoke", "perf-smoke-slo"} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml missing perf gate evidence %q", want)
		}
	}
	mk := read(t, "../Makefile")
	for _, want := range []string{"perf-capacity:", "scripts/perf/run-capacity-calibration.sh"} {
		if !strings.Contains(mk, want) {
			t.Errorf("Makefile missing capacity calibration evidence %q", want)
		}
	}
	for _, want := range []string{"Perf capacity calibration gate", "scripts/perf/run-capacity-calibration.sh --out", "perf-capacity-calibration"} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml missing capacity calibration evidence %q", want)
		}
	}
}

func TestPerfLiveLoadArtifactCoversServedRealisticAndPeakPhases(t *testing.T) {
	doc := read(t, "performance.md")
	for _, want := range []string{
		"make perf-live",
		"scripts/perf/run-local.sh --profile live",
		perf.LiveMeasurementArtifact,
		"realistic",
		"peak",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("performance.md missing live load evidence %q", want)
		}
	}
	capacity := read(t, "performance-capacity.md")
	if !strings.Contains(capacity, perf.LiveMeasurementArtifact) {
		t.Fatalf("performance-capacity.md must cite %s", perf.LiveMeasurementArtifact)
	}
	mk := read(t, "../Makefile")
	if !strings.Contains(mk, "perf-live:") || !strings.Contains(mk, "--profile live") {
		t.Fatal("Makefile must expose a perf-live target that runs the live profile")
	}

	artifact := readLivePerfArtifact(t)
	if !artifact.ServedStack || artifact.StackProfile == "" {
		t.Fatalf("live artifact did not record a served stack profile: %+v", artifact)
	}
	if !artifact.Summary.OK {
		t.Fatalf("live artifact summary is not ok: %+v", artifact.Summary)
	}
	if got, want := artifact.Summary.Measurements, len(perf.HotPaths())*2; got != want {
		t.Fatalf("live artifact measurements = %d, want %d", got, want)
	}
	results := map[string]perf.Result{}
	for _, result := range artifact.Results {
		results[result.HotPath+"/"+result.Phase] = result
		if !result.ServedStack {
			t.Errorf("%s/%s is not marked served_stack", result.HotPath, result.Phase)
		}
		if !strings.Contains(result.Transport, "served-route:") || strings.Contains(result.Transport, "/perf/live/") || strings.Contains(result.Transport, "http-handler") {
			t.Errorf("%s/%s transport = %q, want committed served-route evidence with no perf-only mux", result.HotPath, result.Phase, result.Transport)
		}
		if result.MaxMS <= 0 || result.MaxMS < result.P99MS {
			t.Errorf("%s/%s max latency %.4f must be present and >= p99 %.4f", result.HotPath, result.Phase, result.MaxMS, result.P99MS)
		}
		if result.ThroughputPerSecond <= 0 || result.TargetRatePerSecond <= 0 {
			t.Errorf("%s/%s missing throughput evidence: %+v", result.HotPath, result.Phase, result)
		}
		if result.Errors != 0 {
			t.Errorf("%s/%s recorded errors: %+v", result.HotPath, result.Phase, result.Failures)
		}
		if result.ResourceMetrics == nil || result.ResourceMetrics.Goroutines <= 0 || result.ResourceMetrics.CPUCount <= 0 {
			t.Errorf("%s/%s missing resource metrics: %+v", result.HotPath, result.Phase, result.ResourceMetrics)
		}
		if !result.Met {
			t.Errorf("%s/%s failed live SLO: %+v", result.HotPath, result.Phase, result.Failures)
		}
	}
	for _, slo := range perf.HotPaths() {
		for _, phase := range []string{"realistic", "peak"} {
			key := slo.HotPath + "/" + phase
			result, ok := results[key]
			if !ok {
				t.Errorf("live artifact missing %s", key)
				continue
			}
			if result.SLOID != slo.ID || result.Benchmark != slo.Benchmark {
				t.Errorf("%s metadata = %s/%s, want %s/%s", key, result.SLOID, result.Benchmark, slo.ID, slo.Benchmark)
			}
		}
	}
}

// TestSoakEnduranceGateIsExecutableEvidence pins TRACE-009: the performance/scale
// NFRs are not just prose — the sustained-load (endurance) NFR is backed by an
// executable soak gate (PERF-004). This binds the docs claim to the shipped
// `make soak` target, the soak script, and the analyzer denominator in
// internal/perf, in BOTH directions: if the gate is removed the docs over-claim
// "measured endurance", and if the docs drop the reference the evidence is no longer
// discoverable. It is the served-evidence proof for the soak NFR.
func TestSoakEnduranceGateIsExecutableEvidence(t *testing.T) {
	// The performance doc must point at the executable soak gate so an operator can
	// run the evidence, not just read about it. Rebound off the internal "AnalyzeSoak"
	// symbol and "internal/perf" package path to the customer-facing properties the
	// page states: a runnable soak gate (`make soak` / `scripts/perf/soak.sh`) held to
	// a pass/fail threshold contract that fails on a leak slope or an SLO breach. These
	// keep the "executable evidence, not prose" intent without an internal symbol — if
	// the page stopped describing the gate as a runnable pass/fail contract, this fails.
	doc := read(t, "performance.md")
	for _, want := range []string{"make soak", "make soak-capture", "scripts/perf/capture-soak-series.sh", "scripts/perf/soak.sh", "pass/fail threshold contract", "leak slope or an SLO breach"} {
		if !strings.Contains(doc, want) {
			t.Errorf("performance.md must reference the executable soak gate evidence %q (PERF-004) — TRACE-009", want)
		}
	}

	// The shipped soak gate exists and is a self-testing pass/fail gate (an induced
	// leak MUST fail; a healthy series MUST pass), so it is real evidence not theatre.
	mk := read(t, "../Makefile")
	if !strings.Contains(mk, "soak:") {
		t.Error("Makefile no longer defines the `soak` target; the TRACE-009 endurance evidence is gone — revisit this reality test")
	}
	if !strings.Contains(mk, "soak-capture:") || !strings.Contains(mk, "scripts/perf/soak.sh --in") {
		t.Error("Makefile no longer defines the captured `soak-capture` target that feeds scripts/perf/soak.sh --in — PERF-003")
	}
	for _, want := range []string{"--selftest-fail", "--selftest-ok"} {
		if !strings.Contains(mk, want) {
			t.Errorf("Makefile soak target no longer self-tests with %q; the soak gate is not provably fail-on-leak — TRACE-009", want)
		}
	}
	script := read(t, "../scripts/perf/soak.sh")
	if !strings.Contains(script, "internal/perf") {
		t.Error("scripts/perf/soak.sh no longer consumes the internal/perf denominator; docs, gate, and CI would diverge — TRACE-009")
	}
	capture := read(t, "../scripts/perf/capture-soak-series.sh")
	for _, want := range []string{"./scripts/perf/cmd/soakcapture", "--load-samples", "--step-seconds"} {
		if !strings.Contains(capture, want) {
			t.Errorf("capture-soak-series.sh missing captured-stack argument %q — PERF-003", want)
		}
	}
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"captured soak / leak gate",
		"scripts/perf/capture-soak-series.sh --out",
		"scripts/perf/soak.sh --in",
		"captured-soak-trend",
		"soak-induced-leak.json",
		"--selftest-fail",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml missing captured soak evidence %q — PERF-003", want)
		}
	}

	// The analyzer denominator the docs cite must exist and expose its threshold
	// contract, so a real captured series can be turned into a pass/fail verdict.
	soak := read(t, "../internal/perf/soak.go")
	for _, sym := range []string{"func DefaultSoakThresholds()", "func AnalyzeSoak("} {
		if !strings.Contains(soak, sym) {
			t.Fatalf("internal/perf/soak.go no longer exposes %q; the TRACE-009 endurance evidence has no code anchor — revisit this reality test", sym)
		}
	}
}

func readPerfArtifact(t *testing.T) perf.Report {
	t.Helper()
	var report perf.Report
	data := read(t, "../"+perf.MeasurementArtifact)
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		t.Fatalf("parse %s: %v", perf.MeasurementArtifact, err)
	}
	return report
}

func readLivePerfArtifact(t *testing.T) perf.Report {
	t.Helper()
	var report perf.Report
	data := read(t, "../"+perf.LiveMeasurementArtifact)
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		t.Fatalf("parse %s: %v", perf.LiveMeasurementArtifact, err)
	}
	return report
}

func readCapacityMeasurementArtifact(t *testing.T) perf.CapacityMeasurementReport {
	t.Helper()
	var report perf.CapacityMeasurementReport
	data := read(t, "../"+perf.CapacityMeasurementArtifact)
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		t.Fatalf("parse %s: %v", perf.CapacityMeasurementArtifact, err)
	}
	return report
}

type spineBurstDocArtifact struct {
	Profile             string             `json:"profile"`
	MeasurementArtifact string             `json:"measurement_artifact"`
	Workload            spineBurstWorkload `json:"workload"`
	Samples             []perf.SoakSample  `json:"samples"`
	Summary             struct {
		OK bool `json:"ok"`
	} `json:"summary"`
}

type spineBurstWorkload struct {
	EventEquivalent  int `json:"event_equivalent"`
	OutboxEquivalent int `json:"outbox_equivalent"`
}

func readSpineBurstArtifact(t *testing.T) spineBurstDocArtifact {
	t.Helper()
	var report spineBurstDocArtifact
	data := read(t, "../"+perf.SpineBurstArtifact)
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		t.Fatalf("parse %s: %v", perf.SpineBurstArtifact, err)
	}
	return report
}

func formatInt(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	head := len(s) % 3
	if head == 0 {
		head = 3
	}
	out = append(out, s[:head]...)
	for i := head; i < len(s); i += 3 {
		out = append(out, ',')
		out = append(out, s[i:i+3]...)
	}
	return string(out)
}

func formatGiB(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%d", int(v))
	}
	return fmt.Sprintf("%.1f", v)
}

func formatUSD(n int) string {
	s := formatInt(n)
	return "$" + s
}
