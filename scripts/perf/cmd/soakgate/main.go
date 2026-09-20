// SPDX-License-Identifier: BUSL-1.1

// Command soakgate is the PERF-004 endurance/soak gate driver. It analyzes a
// sustained-load resource series against the committed soak thresholds and exits
// non-zero on a leak slope or SLO breach, emitting a JSON trend report. It mirrors
// scripts/perf/cmd/perfgate (the smoke gate) in shape and house style.
//
// Modes:
//
//	--selftest-ok    feed a synthetic HEALTHY series (must exit 0) — proves the gate
//	                 does not always fail.
//	--selftest-fail  feed a synthetic LEAKING/saturating series (must exit non-zero)
//	                 — proves the gate actually catches a leak.
//	--in <path>      analyze a captured series JSON ({"samples":[...]}) produced by a
//	                 real sustained-load run.
//
// A real soak run (a long, server-backed sustained-load profile that needs embedded
// PostgreSQL and a multi-minute wall-clock budget) captures the series and feeds it
// via --in; that path is exercised in CI's nightly profile, not in a unit test. The
// self-test modes make the gate provably correct without that heavyweight harness.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/perf"
)

type seriesFile struct {
	Profile             string                      `json:"profile,omitempty"`
	Source              string                      `json:"source,omitempty"`
	MeasurementArtifact string                      `json:"measurement_artifact,omitempty"`
	MeasurementMethod   string                      `json:"measurement_method,omitempty"`
	CapacityTier        string                      `json:"capacity_tier,omitempty"`
	Workload            *perf.SoakInputWorkload     `json:"workload,omitempty"`
	SlowUpstream        *perf.SoakInputSlowUpstream `json:"slow_upstream,omitempty"`
	Summary             *perf.SoakInputSummary      `json:"summary,omitempty"`
	Samples             []perf.SoakSample           `json:"samples"`
}

func main() {
	var (
		profile      = flag.String("profile", "soak", "soak profile name")
		out          = flag.String("out", "", "optional JSON trend report path; stdout when empty")
		in           = flag.String("in", "", "captured series JSON to analyze ({\"samples\":[...]})")
		selftestOK   = flag.Bool("selftest-ok", false, "analyze a synthetic healthy series (must exit 0)")
		selftestFail = flag.Bool("selftest-fail", false, "analyze a synthetic leaking series (must exit non-zero)")
		samples      = flag.Int("samples", 120, "synthetic sample count for self-test modes")
		stepSec      = flag.Int("step-seconds", 60, "synthetic inter-sample step for self-test modes")
		printPretty  = flag.Bool("pretty", true, "pretty-print JSON")
	)
	flag.Parse()

	if *selftestOK && *selftestFail {
		fail("choose at most one of --selftest-ok / --selftest-fail")
	}

	var (
		series   []perf.SoakSample
		evidence *perf.SoakInputEvidence
	)
	switch {
	case *selftestOK:
		series = perf.SyntheticHealthySeries(*samples, time.Duration(*stepSec)*time.Second)
		if *profile == "soak" {
			*profile = "selftest-ok"
		}
	case *selftestFail:
		series = perf.SyntheticLeakSeries(*samples, time.Duration(*stepSec)*time.Second)
		if *profile == "soak" {
			*profile = "selftest-fail"
		}
	case *in != "":
		sf, err := loadSeries(*in)
		if err != nil {
			fail("load series %s: %v", *in, err)
		}
		series = sf.Samples
		if sf.Profile != "" && *profile == "soak" {
			*profile = sf.Profile
		}
		evidence = sf.inputEvidence()
	default:
		fail("no input: pass --selftest-ok, --selftest-fail, or --in <series.json>")
	}

	report, err := perf.AnalyzeSoakWithEvidence(*profile, series, perf.DefaultSoakThresholds(), evidence)
	if err != nil {
		fail("analyze soak: %v", err)
	}
	writeReport(*out, *printPretty, report)

	if !report.Summary.OK {
		fail("soak gate failed: %d of %d metrics breached (leak slope or SLO breach)", report.Summary.Breached, report.Summary.Metrics)
	}
}

func writeReport(out string, printPretty bool, report perf.SoakReport) {
	var data []byte
	var err error
	if printPretty {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}
	if err != nil {
		fail("marshal report: %v", err)
	}
	data = append(data, '\n')
	if out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail("write stdout: %v", err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil { // #nosec G301 -- developer tool writing repo/dist artifacts; the mode is intentional (CWE-276)
			fail("create output dir: %v", err)
		}
		if err := os.WriteFile(out, data, 0o644); err != nil { // #nosec G306 -- developer tool writing repo/dist artifacts; the mode is intentional (CWE-276)
			fail("write %s: %v", out, err)
		}
	}
}

func loadSeries(path string) (seriesFile, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
	if err != nil {
		return seriesFile{}, err
	}
	var sf seriesFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return seriesFile{}, err
	}
	if len(sf.Samples) < 2 {
		return seriesFile{}, fmt.Errorf("series has %d samples, need at least 2", len(sf.Samples))
	}
	return sf, nil
}

func (sf seriesFile) inputEvidence() *perf.SoakInputEvidence {
	if sf.Source == "" &&
		sf.MeasurementArtifact == "" &&
		sf.MeasurementMethod == "" &&
		sf.CapacityTier == "" &&
		sf.Workload == nil &&
		sf.SlowUpstream == nil &&
		sf.Summary == nil {
		return nil
	}
	return &perf.SoakInputEvidence{
		Source:              sf.Source,
		MeasurementArtifact: sf.MeasurementArtifact,
		MeasurementMethod:   sf.MeasurementMethod,
		CapacityTier:        sf.CapacityTier,
		Workload:            sf.Workload,
		SlowUpstream:        sf.SlowUpstream,
		Summary:             sf.Summary,
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
