package perf

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// PERF-004: the perf SMOKE gate (perfgate / scripts/perf/run-local.sh) measures
// single-shot hot-path latency, but nothing tied a SUSTAINED-load profile to a
// pass/fail threshold. A leak only shows up under endurance: RSS/heap that climbs,
// goroutines/FDs that never come back, a DB pool that saturates, a projection/outbox
// lag that grows without bound, storage that only goes up. This file is the soak
// analyzer behind that gate. It takes a time-ordered series of resource samples
// gathered during a sustained-load run and FAILS (OK=false) on either an SLO breach
// (a metric exceeds its ceiling) or a leak slope (a metric trends up faster than its
// allowed per-minute drift). It emits a JSON trend report so a regression is
// diagnosable, not just red. The shape mirrors smoke.go's Report/Summary so docs and
// CI consume one schema family.
//
// The analyzer is pure: it does not start a server (that needs embedded PostgreSQL
// and a long wall-clock budget, neither of which belongs in a unit test or this
// sandbox). The soakgate command feeds it either a real captured series or, in
// self-test mode, a synthetic healthy/leaking series — which is what makes the gate
// self-testable: an induced rising-RSS series MUST fail, a flat series MUST pass.

// SoakSample is one observation of the tracked endurance metrics at a point in time.
// Counters (signer restarts, queue rejects) are cumulative; gauges (rss, heap,
// goroutines, fds, pool, lag, storage) are instantaneous. Zero values are valid.
type SoakSample struct {
	T                   time.Time `json:"t"`
	RSSBytes            float64   `json:"rss_bytes"`
	HeapBytes           float64   `json:"heap_bytes"`
	Goroutines          float64   `json:"goroutines"`
	OpenFDs             float64   `json:"open_fds"`
	DBPoolInUse         float64   `json:"db_pool_in_use"`
	DBPoolSize          float64   `json:"db_pool_size"`
	QueueRejects        float64   `json:"queue_rejects"`         // cumulative
	SignerRestarts      float64   `json:"signer_restarts"`       // cumulative
	ProjectionLagEvents float64   `json:"projection_lag_events"` // gauge
	OutboxLagItems      float64   `json:"outbox_lag_items"`      // gauge
	StorageBytes        float64   `json:"storage_bytes"`         // gauge (monotonic growth expected)
	P95MS               float64   `json:"p95_ms"`
	P99MS               float64   `json:"p99_ms"`
}

// SoakThresholds is the committed soak contract: the ceiling each metric may not
// exceed, and the maximum per-minute upward slope a gauge may have before it is
// treated as a leak. A zero LeakSlopePerMin for a gauge means "no sustained growth
// allowed" (any positive trend beyond Tolerance fails). Counters use a per-minute
// rate ceiling instead of a slope.
type SoakThresholds struct {
	// Gauge ceilings (absolute). A sample above the ceiling is an SLO breach.
	MaxRSSBytes            float64 `json:"max_rss_bytes"`
	MaxHeapBytes           float64 `json:"max_heap_bytes"`
	MaxGoroutines          float64 `json:"max_goroutines"`
	MaxOpenFDs             float64 `json:"max_open_fds"`
	MaxDBPoolUtilization   float64 `json:"max_db_pool_utilization"` // in_use/size, 0..1
	MaxProjectionLagEvents float64 `json:"max_projection_lag_events"`
	MaxOutboxLagItems      float64 `json:"max_outbox_lag_items"`
	MaxP95MS               float64 `json:"max_p95_ms"`
	MaxP99MS               float64 `json:"max_p99_ms"`

	// Leak slope ceilings (units per minute). A least-squares slope above the limit
	// (beyond a small relative tolerance) is a leak failure even if no single sample
	// breached a ceiling.
	MaxRSSGrowthPerMin   float64 `json:"max_rss_growth_bytes_per_min"`
	MaxHeapGrowthPerMin  float64 `json:"max_heap_growth_bytes_per_min"`
	MaxGoroutineSlope    float64 `json:"max_goroutine_slope_per_min"`
	MaxFDSlope           float64 `json:"max_fd_slope_per_min"`
	MaxProjLagSlope      float64 `json:"max_projection_lag_slope_per_min"`
	MaxOutboxLagSlope    float64 `json:"max_outbox_lag_slope_per_min"`
	MaxStorageGrowthRate float64 `json:"max_storage_growth_bytes_per_min"`

	// Counter rate ceilings (events per minute).
	MaxQueueRejectsPerMin   float64 `json:"max_queue_rejects_per_min"`
	MaxSignerRestartsPerMin float64 `json:"max_signer_restarts_per_min"`
}

// DefaultSoakThresholds returns conservative endurance thresholds aligned with the
// CAP-SMALL/MEDIUM capacity tiers in the perf contract. They are deliberately
// loose on absolute ceilings (a soak is about TRENDS, not a one-off spike) and
// strict on slopes: a steadily climbing RSS/heap/goroutine/FD/lag is a leak.
func DefaultSoakThresholds() SoakThresholds {
	const mib = 1024 * 1024
	return SoakThresholds{
		MaxRSSBytes:            4096 * mib, // CAP-SMALL control-plane memory ceiling (4 GiB)
		MaxHeapBytes:           3072 * mib,
		MaxGoroutines:          20000,
		MaxOpenFDs:             8192,
		MaxDBPoolUtilization:   0.90,
		MaxProjectionLagEvents: 50,
		MaxOutboxLagItems:      500,
		MaxP95MS:               300,
		MaxP99MS:               750,

		// Slopes: tolerate small steady-state churn, fail a sustained climb. A real
		// soak is long enough that even a slow leak accumulates a clear slope.
		MaxRSSGrowthPerMin:   8 * mib, // > ~0.5 GiB/hr is a leak at this scale
		MaxHeapGrowthPerMin:  6 * mib,
		MaxGoroutineSlope:    5,        // goroutines should plateau, not creep
		MaxFDSlope:           2,        // FDs must be returned
		MaxProjLagSlope:      1,        // lag must not grow without bound
		MaxOutboxLagSlope:    2,        // outbox must drain
		MaxStorageGrowthRate: 64 * mib, // storage grows, but a runaway is a failure

		MaxQueueRejectsPerMin:   60,  // some shedding is healthy backpressure; a flood is not
		MaxSignerRestartsPerMin: 0.2, // ~ at most one restart per 5 minutes
	}
}

// MetricTrend is the per-metric verdict in the trend report: its least-squares
// slope per minute, its peak, the applicable limit, and whether it failed (and why).
type MetricTrend struct {
	Metric      string  `json:"metric"`
	Kind        string  `json:"kind"` // "gauge-ceiling" | "leak-slope" | "counter-rate"
	SlopePerMin float64 `json:"slope_per_min"`
	Peak        float64 `json:"peak"`
	Limit       float64 `json:"limit"`
	Observed    float64 `json:"observed"` // the value compared against Limit (peak or slope or rate)
	OK          bool    `json:"ok"`
	Detail      string  `json:"detail,omitempty"`
}

// SoakInputEvidence is optional provenance carried from a captured series into
// the trend report. Plain self-tests do not set it; the spine-burst series uses it
// to keep the embedded datastore, replay, and outbox receipt visible after the
// generic soak analyzer has reduced the samples to trend metrics.
type SoakInputEvidence struct {
	Source              string                 `json:"source,omitempty"`
	MeasurementArtifact string                 `json:"measurement_artifact,omitempty"`
	MeasurementMethod   string                 `json:"measurement_method,omitempty"`
	CapacityTier        string                 `json:"capacity_tier,omitempty"`
	Workload            *SoakInputWorkload     `json:"workload,omitempty"`
	SlowUpstream        *SoakInputSlowUpstream `json:"slow_upstream,omitempty"`
	Summary             *SoakInputSummary      `json:"summary,omitempty"`
}

// SoakInputWorkload carries the scale knobs from a captured soak-compatible run.
type SoakInputWorkload struct {
	Tenants               int    `json:"tenants"`
	Agents                int    `json:"agents"`
	EventEquivalent       int    `json:"event_equivalent"`
	OutboxEquivalent      int    `json:"outbox_equivalent"`
	ProjectionLagTarget   int    `json:"projection_lag_target"`
	OutboxBacklogTarget   int    `json:"outbox_backlog_target"`
	QueueRejectsCaptured  bool   `json:"queue_rejects_captured"`
	DBPoolCaptured        bool   `json:"db_pool_captured"`
	ServedHotPathArtifact string `json:"served_hot_path_artifact,omitempty"`
}

// SoakInputSlowUpstream describes a deliberately delayed external destination
// used to prove the outbox backlog remains bounded.
type SoakInputSlowUpstream struct {
	Injected        bool   `json:"injected"`
	Destination     string `json:"destination,omitempty"`
	DelayMS         int64  `json:"delay_ms,omitempty"`
	BoundedBacklog  int    `json:"bounded_backlog,omitempty"`
	DeliveryPattern string `json:"delivery_pattern,omitempty"`
}

// SoakInputSummary keeps the source receipt's own roll-up alongside the generic
// trend analysis roll-up emitted by the soak gate.
type SoakInputSummary struct {
	OK                  bool         `json:"ok"`
	Samples             int          `json:"samples,omitempty"`
	AppendedEvents      int          `json:"appended_events,omitempty"`
	ReplayedEvents      int          `json:"replayed_events,omitempty"`
	ProjectionLagEvents int          `json:"projection_lag_events,omitempty"`
	OutboxQueued        int          `json:"outbox_queued,omitempty"`
	OutboxPending       int          `json:"outbox_pending,omitempty"`
	QueueRejects        int          `json:"queue_rejects,omitempty"`
	SoakSummary         *SoakSummary `json:"soak_summary,omitempty"`
}

// SoakReport is the JSON trend report the gate emits. OK=false fails the gate.
type SoakReport struct {
	SchemaVersion int                `json:"schema_version"`
	Profile       string             `json:"profile"`
	GeneratedAt   string             `json:"generated_at"`
	InputEvidence *SoakInputEvidence `json:"input_evidence,omitempty"`
	Samples       int                `json:"samples"`
	DurationSec   float64            `json:"duration_sec"`
	Trends        []MetricTrend      `json:"trends"`
	Summary       SoakSummary        `json:"summary"`
}

// SoakSummary is the pass/fail roll-up.
type SoakSummary struct {
	Metrics  int  `json:"metrics"`
	Breached int  `json:"breached"`
	OK       bool `json:"ok"`
}

// relTolerance is the slack applied to slope/rate comparisons so a numerically
// negligible positive drift (floating-point noise, one-sample jitter) does not fail
// a gate that is otherwise flat.
const relTolerance = 1e-9

// AnalyzeSoak builds the trend report from a captured series against the thresholds.
// It fails on the FIRST of: a gauge that breached its ceiling at any sample, a gauge
// whose upward slope exceeds its leak limit, or a counter whose per-minute rate
// exceeds its ceiling. It needs at least two samples spanning a positive duration to
// compute a slope; fewer is a usage error.
func AnalyzeSoak(profile string, series []SoakSample, th SoakThresholds) (SoakReport, error) {
	return AnalyzeSoakWithEvidence(profile, series, th, nil)
}

// AnalyzeSoakWithEvidence builds the same trend report as AnalyzeSoak and carries
// optional input provenance into the JSON output.
func AnalyzeSoakWithEvidence(profile string, series []SoakSample, th SoakThresholds, evidence *SoakInputEvidence) (SoakReport, error) {
	if len(series) < 2 {
		return SoakReport{}, fmt.Errorf("perf soak: need at least 2 samples, got %d", len(series))
	}
	ordered := append([]SoakSample(nil), series...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].T.Before(ordered[j].T) })
	dur := ordered[len(ordered)-1].T.Sub(ordered[0].T)
	if dur <= 0 {
		return SoakReport{}, fmt.Errorf("perf soak: series must span a positive duration")
	}
	mins := dur.Minutes()

	report := SoakReport{
		SchemaVersion: 1,
		Profile:       profile,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		InputEvidence: evidence,
		Samples:       len(ordered),
		DurationSec:   dur.Seconds(),
	}

	add := func(t MetricTrend) {
		report.Trends = append(report.Trends, t)
		report.Summary.Metrics++
		if !t.OK {
			report.Summary.Breached++
		}
	}

	// Gauge ceilings: fail if any sample exceeded the ceiling.
	gaugeCeil := func(name string, get func(SoakSample) float64, limit float64) {
		if limit <= 0 {
			return
		}
		peak := peakOf(ordered, get)
		ok := peak <= limit
		add(MetricTrend{Metric: name, Kind: "gauge-ceiling", Limit: limit, Peak: peak, Observed: peak,
			SlopePerMin: slopePerMin(ordered, get), OK: ok,
			Detail: ceilDetail(ok, peak, limit)})
	}
	gaugeCeil("rss_bytes", func(s SoakSample) float64 { return s.RSSBytes }, th.MaxRSSBytes)
	gaugeCeil("heap_bytes", func(s SoakSample) float64 { return s.HeapBytes }, th.MaxHeapBytes)
	gaugeCeil("goroutines", func(s SoakSample) float64 { return s.Goroutines }, th.MaxGoroutines)
	gaugeCeil("open_fds", func(s SoakSample) float64 { return s.OpenFDs }, th.MaxOpenFDs)
	gaugeCeil("projection_lag_events", func(s SoakSample) float64 { return s.ProjectionLagEvents }, th.MaxProjectionLagEvents)
	gaugeCeil("outbox_lag_items", func(s SoakSample) float64 { return s.OutboxLagItems }, th.MaxOutboxLagItems)
	gaugeCeil("p95_ms", func(s SoakSample) float64 { return s.P95MS }, th.MaxP95MS)
	gaugeCeil("p99_ms", func(s SoakSample) float64 { return s.P99MS }, th.MaxP99MS)

	// DB pool utilization ceiling (derived gauge).
	if th.MaxDBPoolUtilization > 0 {
		peak := peakOf(ordered, dbPoolUtil)
		ok := peak <= th.MaxDBPoolUtilization
		add(MetricTrend{Metric: "db_pool_utilization", Kind: "gauge-ceiling", Limit: th.MaxDBPoolUtilization,
			Peak: peak, Observed: peak, SlopePerMin: slopePerMin(ordered, dbPoolUtil), OK: ok,
			Detail: ceilDetail(ok, peak, th.MaxDBPoolUtilization)})
	}

	// Leak slopes: fail if the upward per-minute slope exceeds the limit.
	leakSlope := func(name string, get func(SoakSample) float64, limit float64) {
		slope := slopePerMin(ordered, get)
		ok := slope <= limit+math.Abs(limit)*relTolerance+relTolerance
		add(MetricTrend{Metric: name, Kind: "leak-slope", Limit: limit, SlopePerMin: slope,
			Observed: slope, Peak: peakOf(ordered, get), OK: ok,
			Detail: slopeDetail(ok, slope, limit)})
	}
	leakSlope("rss_bytes_growth", func(s SoakSample) float64 { return s.RSSBytes }, th.MaxRSSGrowthPerMin)
	leakSlope("heap_bytes_growth", func(s SoakSample) float64 { return s.HeapBytes }, th.MaxHeapGrowthPerMin)
	leakSlope("goroutine_growth", func(s SoakSample) float64 { return s.Goroutines }, th.MaxGoroutineSlope)
	leakSlope("fd_growth", func(s SoakSample) float64 { return s.OpenFDs }, th.MaxFDSlope)
	leakSlope("projection_lag_growth", func(s SoakSample) float64 { return s.ProjectionLagEvents }, th.MaxProjLagSlope)
	leakSlope("outbox_lag_growth", func(s SoakSample) float64 { return s.OutboxLagItems }, th.MaxOutboxLagSlope)
	leakSlope("storage_growth", func(s SoakSample) float64 { return s.StorageBytes }, th.MaxStorageGrowthRate)

	// Counter rates: cumulative delta over the window, per minute.
	counterRate := func(name string, get func(SoakSample) float64, limit float64) {
		delta := get(ordered[len(ordered)-1]) - get(ordered[0])
		if delta < 0 {
			delta = 0 // a counter reset (restart) is not a negative rate
		}
		rate := delta / mins
		ok := rate <= limit+math.Abs(limit)*relTolerance+relTolerance
		add(MetricTrend{Metric: name, Kind: "counter-rate", Limit: limit, Observed: rate,
			Peak: get(ordered[len(ordered)-1]), OK: ok,
			Detail: rateDetail(ok, rate, limit)})
	}
	counterRate("queue_rejects_rate", func(s SoakSample) float64 { return s.QueueRejects }, th.MaxQueueRejectsPerMin)
	counterRate("signer_restarts_rate", func(s SoakSample) float64 { return s.SignerRestarts }, th.MaxSignerRestartsPerMin)

	report.Summary.OK = report.Summary.Breached == 0
	return report, nil
}

func dbPoolUtil(s SoakSample) float64 {
	if s.DBPoolSize <= 0 {
		return 0
	}
	return s.DBPoolInUse / s.DBPoolSize
}

func peakOf(series []SoakSample, get func(SoakSample) float64) float64 {
	peak := math.Inf(-1)
	for _, s := range series {
		if v := get(s); v > peak {
			peak = v
		}
	}
	if math.IsInf(peak, -1) {
		return 0
	}
	return peak
}

// slopePerMin is the ordinary least-squares slope of get(sample) against elapsed
// minutes from the first sample. Positive means the metric trends up over time.
func slopePerMin(series []SoakSample, get func(SoakSample) float64) float64 {
	n := float64(len(series))
	t0 := series[0].T
	var sx, sy, sxx, sxy float64
	for _, s := range series {
		x := s.T.Sub(t0).Minutes()
		y := get(s)
		sx += x
		sy += y
		sxx += x * x
		sxy += x * y
	}
	denom := n*sxx - sx*sx
	if denom == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / denom
}

func ceilDetail(ok bool, peak, limit float64) string {
	if ok {
		return ""
	}
	return fmt.Sprintf("peak %.3g exceeded ceiling %.3g", peak, limit)
}

func slopeDetail(ok bool, slope, limit float64) string {
	if ok {
		return ""
	}
	return fmt.Sprintf("leak: slope %.3g/min exceeded limit %.3g/min", slope, limit)
}

func rateDetail(ok bool, rate, limit float64) string {
	if ok {
		return ""
	}
	return fmt.Sprintf("rate %.3g/min exceeded limit %.3g/min", rate, limit)
}

// SyntheticHealthySeries returns a flat, steady-state series that PASSES the default
// thresholds: RSS/heap oscillate around a plateau (GC sawtooth), goroutines/FDs/lag
// are stable, storage grows slowly within budget, and counters are quiet. It is the
// `--selftest-ok` fixture: a gate that fails this is broken.
func SyntheticHealthySeries(samples int, step time.Duration) []SoakSample {
	const mib = 1024 * 1024
	if samples < 2 {
		samples = 2
	}
	start := time.Unix(0, 0).UTC()
	out := make([]SoakSample, samples)
	for i := 0; i < samples; i++ {
		// Sawtooth around a plateau: heap rises then GC drops it; no net trend.
		saw := float64(i%5) * 2 * mib
		out[i] = SoakSample{
			T:                   start.Add(time.Duration(i) * step),
			RSSBytes:            512*mib + saw,
			HeapBytes:           300*mib + saw,
			Goroutines:          420 + float64(i%3),
			OpenFDs:             128 + float64(i%2),
			DBPoolInUse:         6 + float64(i%2),
			DBPoolSize:          16,
			QueueRejects:        float64(i / 20), // ~ trivial steady shedding
			SignerRestarts:      0,
			ProjectionLagEvents: 3 + float64(i%2),
			OutboxLagItems:      4 + float64(i%3),
			StorageBytes:        1024*mib + float64(i)*mib, // ~1 MiB/sample, within budget at minute scale
			P95MS:               40 + float64(i%3),
			P99MS:               90 + float64(i%4),
		}
	}
	return out
}

// SyntheticLeakSeries returns a series with an induced RSS/heap/goroutine/FD/lag
// LEAK (a clear upward slope) and a saturating DB pool. It FAILS the default
// thresholds. It is the `--selftest-fail` fixture that proves the gate actually
// catches a leak/saturation rather than always passing.
func SyntheticLeakSeries(samples int, step time.Duration) []SoakSample {
	const mib = 1024 * 1024
	if samples < 2 {
		samples = 2
	}
	start := time.Unix(0, 0).UTC()
	out := make([]SoakSample, samples)
	for i := 0; i < samples; i++ {
		f := float64(i)
		out[i] = SoakSample{
			T:                   start.Add(time.Duration(i) * step),
			RSSBytes:            512*mib + f*40*mib, // steep, sustained climb (leak)
			HeapBytes:           300*mib + f*30*mib,
			Goroutines:          420 + f*50,    // goroutines never returned
			OpenFDs:             128 + f*10,    // FDs leaked
			DBPoolInUse:         minF(16, 6+f), // pool saturates toward size
			DBPoolSize:          16,
			QueueRejects:        f * 200, // flood of rejections (saturation)
			SignerRestarts:      f * 0.5, // restart storm
			ProjectionLagEvents: 3 + f*4, // lag grows without bound
			OutboxLagItems:      4 + f*8,
			StorageBytes:        1024*mib + f*128*mib,
			P95MS:               40 + f*30,
			P99MS:               90 + f*60,
		}
	}
	return out
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
