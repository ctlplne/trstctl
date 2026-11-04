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

// CI-L37 (owner note 2026-11-03, bar item 2): each captured sample records
// api.issuance's requests and throughput, and the report gives the overall
// rate — every request over the time spent issuing them — with the lowest
// sample beside it. It is reported, never judged: a series whose issuance
// rate is under 25/s still passes on its gauges, and a series without the
// fields reports no rate.
func TestSoakReportCarriesIssuanceRateUnjudged(t *testing.T) {
	series := SyntheticHealthySeries(4, time.Minute)
	for i, rate := range []float64{30, 20, 30, 20} {
		series[i].IssuanceRequests, series[i].IssuanceRatePerSecond = 10, rate
	}
	rep, err := AnalyzeSoak("issuance-rate", series, DefaultSoakThresholds())
	if err != nil {
		t.Fatal(err)
	}
	// 40 requests in 4×(10/30) + ... = 2×0.333 s + 2×0.5 s = 1.667 s: 24/s.
	if rep.Issuance == nil || rep.Issuance.Samples != 4 || rep.Issuance.Requests != 40 ||
		rep.Issuance.OverallPerSecond < 23.999 || rep.Issuance.OverallPerSecond > 24.001 ||
		rep.Issuance.LowestSamplePerSecond != 20 || rep.Issuance.LowestSampleAt != series[1].T.UTC().Format(time.RFC3339) {
		t.Fatalf("issuance rate = %+v", rep.Issuance)
	}
	if !rep.Summary.OK {
		t.Fatalf("an issuance rate under 25/s failed the soak; it must be reported, never judged: %+v", rep.Summary)
	}
	plain, err := AnalyzeSoak("no-rate", SyntheticHealthySeries(4, time.Minute), DefaultSoakThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if plain.Issuance != nil || plain.Summary != rep.Summary {
		t.Fatalf("a series without issuance fields: rate %+v, summary %+v vs %+v", plain.Issuance, plain.Summary, rep.Summary)
	}
}
