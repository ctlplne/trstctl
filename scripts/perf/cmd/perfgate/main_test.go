// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/perf"
)

func TestPerfGateExitsNonzeroForInjectedRuntimeBreaches(t *testing.T) {
	obsPath := filepath.Join(t.TempDir(), "breached-observations.json")
	if err := os.WriteFile(obsPath, []byte(`{
  "api.issuance": {"queue_saturation": 0.81},
  "api.inventory": {"error_budget_percent": 0.11},
  "spine.projection_replay": {"projection_lag_events": 51}
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "run", ".", "--samples", "4", "--pretty=false", "--observations", obsPath) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("perfgate passed with injected runtime breaches:\n%s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("perfgate error = %T %v, want exit error; output:\n%s", err, err, out)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("perfgate exit code = 0 with injected runtime breaches:\n%s", out)
	}
	for _, want := range [][]byte{
		[]byte("perf gate failed"),
		[]byte("queue saturation"),
		[]byte("error budget"),
		[]byte("projection lag"),
	} {
		if !bytes.Contains(out, want) {
			t.Fatalf("perfgate output missing %q:\n%s", want, out)
		}
	}
}

func TestPerfGateRunsLiveProfile(t *testing.T) {
	report, err := runProfile("live", 64, nil)
	if err != nil {
		t.Fatalf("run live profile: %v", err)
	}
	if !raceInstrumentationEnabled {
		if err := liveProfileFailure(report); err != nil {
			t.Fatal(err)
		}
	}
	for _, result := range report.Results {
		if result.Errors != 0 {
			err := liveProfileFailure(report)
			if err == nil {
				err = fmt.Errorf("live profile %s/%s recorded %d operation errors", result.HotPath, result.Phase, result.Errors)
			}
			t.Fatal(err)
		}
	}
	if report.Profile != "live" || !report.ServedStack || report.MeasurementArtifact != perf.LiveMeasurementArtifact {
		t.Fatalf("bad live profile metadata: %+v", report)
	}
	if got, want := len(report.Results), len(perf.HotPaths())*2; got != want {
		t.Fatalf("live result count = %d, want %d", got, want)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode live output: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("decode live output as map: %v\n%s", err, data)
	}
	evidence, ok := raw["event_spine_burst"].(map[string]any)
	if !ok {
		t.Fatalf("live report missing event_spine_burst evidence: %s", data)
	}
	if evidence["artifact"] != perf.SpineBurstArtifact {
		t.Fatalf("event_spine_burst.artifact = %v, want %s", evidence["artifact"], perf.SpineBurstArtifact)
	}
	if cmd, _ := evidence["command"].(string); !strings.Contains(cmd, "scripts/perf/run-spine-burst.sh") || !strings.Contains(cmd, "scripts/perf/soak.sh --in") {
		t.Fatalf("event_spine_burst.command = %q, want capture plus soak analyzer", cmd)
	}
}

func TestLiveProfileFailurePreservesFailedReceipt(t *testing.T) {
	err := liveProfileFailure(perf.Report{
		Summary: perf.Summary{HotPaths: 8, Failed: 1},
		Results: []perf.Result{{
			HotPath: "api.issuance",
			Phase:   "peak",
			Failures: []string{
				"p50 51.00ms exceeds 50.00ms",
			},
		}},
	})
	if err == nil {
		t.Fatal("failed live profile returned no error")
	}
	for _, want := range []string{"1 of 8", "api.issuance", "peak", "51.00ms exceeds 50.00ms"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("failed live profile evidence missing %q:\n%s", want, err)
		}
	}
}

func liveProfileFailure(report perf.Report) error {
	if report.Summary.OK {
		return nil
	}
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode failed live profile receipt: %w", err)
	}
	return fmt.Errorf("perfgate live failed: %d of %d hot paths missed SLO\nfailure receipt:\n%s", report.Summary.Failed, report.Summary.HotPaths, data)
}

func TestRunProfileUsesSmokeLiveAndRejectsUnknownProfiles(t *testing.T) {
	smoke, err := runProfile("", 1, nil)
	if err != nil {
		t.Fatalf("runProfile smoke: %v", err)
	}
	if smoke.Profile != "smoke" || smoke.ServedStack {
		t.Fatalf("smoke profile metadata = %+v", smoke)
	}

	live, err := runProfile("live-load", 1, nil)
	if err != nil {
		t.Fatalf("runProfile live-load: %v", err)
	}
	if live.Profile != "live" || !live.ServedStack || live.MeasurementArtifact != perf.LiveMeasurementArtifact {
		t.Fatalf("live profile metadata = %+v", live)
	}

	breached, err := runProfile("smoke", 1, map[string]perf.Observation{
		"api.issuance":            {QueueSaturation: 0.99},
		"spine.projection_replay": {ProjectionLagEvents: 999},
		"api.secrets":             {ErrorBudgetPercent: 0.5},
	})
	if err != nil {
		t.Fatalf("runProfile breached smoke: %v", err)
	}
	if breached.Summary.OK || breached.Summary.Failed == 0 {
		t.Fatalf("breached observations should fail the report: %+v", breached.Summary)
	}

	if _, err := runProfile("bogus", 1, nil); err == nil || !strings.Contains(err.Error(), "unknown perf profile") {
		t.Fatalf("unknown profile error = %v, want unknown perf profile", err)
	}
}
