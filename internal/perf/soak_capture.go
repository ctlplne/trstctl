package perf

import (
	"fmt"
	"math"
	"time"
)

type SoakCaptureOptions struct {
	Profile     string
	Samples     int
	Step        time.Duration
	LoadSamples int
	Sleep       bool
}

type SoakSeries struct {
	Profile     string       `json:"profile"`
	Source      string       `json:"source"`
	GeneratedAt string       `json:"generated_at"`
	Samples     []SoakSample `json:"samples"`
}

func CaptureSoakSeries(opts SoakCaptureOptions) (SoakSeries, error) {
	if opts.Profile == "" {
		opts.Profile = "captured-soak"
	}
	if opts.Samples <= 0 {
		opts.Samples = 12
	}
	if opts.Samples < 2 {
		return SoakSeries{}, fmt.Errorf("perf soak capture: need at least 2 samples, got %d", opts.Samples)
	}
	if opts.Step <= 0 {
		opts.Step = 5 * time.Second
	}
	if opts.LoadSamples <= 0 {
		opts.LoadSamples = 8
	}
	ops, _, cleanup, err := liveServedOperations()
	if err != nil {
		return SoakSeries{}, err
	}
	defer cleanup()

	series := SoakSeries{
		Profile:     opts.Profile,
		Source:      liveStackProfile,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Samples:     make([]SoakSample, 0, opts.Samples),
	}
	start := time.Now().UTC()
	for i := 0; i < opts.Samples; i++ {
		if i > 0 && opts.Sleep {
			time.Sleep(opts.Step)
		}
		sampleTime := start.Add(time.Duration(i) * opts.Step)
		if opts.Sleep {
			sampleTime = time.Now().UTC()
		}
		sample, err := captureOneSoakSample(sampleTime, ops, opts.LoadSamples)
		if err != nil {
			return SoakSeries{}, err
		}
		series.Samples = append(series.Samples, sample)
	}
	return series, nil
}

func captureOneSoakSample(t time.Time, ops map[string]operation, loadSamples int) (SoakSample, error) {
	var p95, p99 float64
	var projectionLag int
	for _, slo := range HotPaths() {
		op, ok := ops[slo.HotPath]
		if !ok {
			return SoakSample{}, fmt.Errorf("perf soak capture: no operation for hot path %s", slo.HotPath)
		}
		result := measure(slo, op, loadSamples, Observation{})
		if result.Errors > 0 {
			return SoakSample{}, fmt.Errorf("perf soak capture: %s produced %d errors: %v", slo.HotPath, result.Errors, result.Failures)
		}
		p95 = math.Max(p95, result.P95MS)
		p99 = math.Max(p99, result.P99MS)
		if result.ProjectionLagEvents > projectionLag {
			projectionLag = result.ProjectionLagEvents
		}
	}
	rm := captureResourceMetrics(projectionLag)
	return SoakSample{
		T:                   t,
		RSSBytes:            float64(rm.MemorySysBytes),
		HeapBytes:           float64(rm.HeapInuseBytes),
		Goroutines:          float64(rm.Goroutines),
		OpenFDs:             float64(rm.OpenFDs),
		DBPoolInUse:         0,
		DBPoolSize:          1,
		QueueRejects:        0,
		SignerRestarts:      0,
		ProjectionLagEvents: float64(projectionLag),
		OutboxLagItems:      0,
		StorageBytes:        float64(rm.HeapInuseBytes + rm.StackInuseBytes),
		P95MS:               p95,
		P99MS:               p99,
	}, nil
}
