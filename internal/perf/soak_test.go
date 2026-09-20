// SPDX-License-Identifier: BUSL-1.1

package perf

import (
	"strings"
	"testing"
	"time"
)

// TestSoakHealthySeriesPasses is the PERF-004 healthy half: a flat, steady-state
// endurance series (GC sawtooth, stable goroutines/FDs/lag, bounded storage growth)
// passes the default soak thresholds. A gate that fails this is broken.
func TestSoakHealthySeriesPasses(t *testing.T) {
	series := SyntheticHealthySeries(120, time.Minute)
	rep, err := AnalyzeSoak("selftest-ok", series, DefaultSoakThresholds())
	if err != nil {
		t.Fatalf("AnalyzeSoak: %v", err)
	}
	if !rep.Summary.OK {
		var bad []string
		for _, tr := range rep.Trends {
			if !tr.OK {
				bad = append(bad, tr.Metric+": "+tr.Detail)
			}
		}
		t.Fatalf("healthy series should pass, breached=%d: %s", rep.Summary.Breached, strings.Join(bad, "; "))
	}
	if rep.Summary.Metrics == 0 {
		t.Fatal("expected the report to evaluate metrics")
	}
}

// TestSoakLeakSeriesFails is the PERF-004 acceptance: an induced
// leak/saturation series (climbing RSS/heap/goroutines/FDs/lag, saturating pool,
// reject flood, restart storm) FAILS the gate. This is the self-test guarantee that
// the gate catches a leak rather than always passing.
func TestSoakLeakSeriesFails(t *testing.T) {
	series := SyntheticLeakSeries(120, time.Minute)
	rep, err := AnalyzeSoak("selftest-fail", series, DefaultSoakThresholds())
	if err != nil {
		t.Fatalf("AnalyzeSoak: %v", err)
	}
	if rep.Summary.OK {
		t.Fatalf("leak series must fail the soak gate, but it passed: %+v", rep.Summary)
	}
	// The RSS leak slope in particular must be flagged.
	var sawRSSLeak bool
	for _, tr := range rep.Trends {
		if tr.Metric == "rss_bytes_growth" && tr.Kind == "leak-slope" && !tr.OK {
			sawRSSLeak = true
		}
	}
	if !sawRSSLeak {
		t.Fatalf("expected the RSS leak slope to be flagged, trends=%+v", rep.Trends)
	}
}

// TestSoakDetectsLeakWithinCeiling proves the slope check is independent of the
// absolute ceiling: a metric can leak (steady upward slope) while every sample is
// still under its ceiling, and the gate must still fail it. Without this, a slow
// leak that never reaches the ceiling within the window would slip through.
func TestSoakDetectsLeakWithinCeiling(t *testing.T) {
	const mib = 1024 * 1024
	start := time.Unix(0, 0).UTC()
	var series []SoakSample
	for i := 0; i < 60; i++ {
		series = append(series, SoakSample{
			T: start.Add(time.Duration(i) * time.Minute),
			// Climbs 20 MiB/min — well under the 4 GiB ceiling for the whole hour,
			// but far above the 8 MiB/min leak-slope limit.
			RSSBytes:   600*mib + float64(i)*20*mib,
			DBPoolSize: 16,
		})
	}
	rep, err := AnalyzeSoak("leak-within-ceiling", series, DefaultSoakThresholds())
	if err != nil {
		t.Fatalf("AnalyzeSoak: %v", err)
	}
	if rep.Summary.OK {
		t.Fatal("a sub-ceiling RSS leak slope must still fail the gate")
	}
}

// TestSoakRequiresTwoSamples guards the usage contract: a slope needs at least two
// samples over a positive duration.
func TestSoakRequiresTwoSamples(t *testing.T) {
	if _, err := AnalyzeSoak("x", SyntheticHealthySeries(1, time.Minute)[:1], DefaultSoakThresholds()); err == nil {
		t.Fatal("expected an error for a single-sample series")
	}
}
