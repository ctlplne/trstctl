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
	Sampler     SoakMetricSampler
}

type SoakSeries struct {
	Profile     string       `json:"profile"`
	Source      string       `json:"source"`
	GeneratedAt string       `json:"generated_at"`
	Samples     []SoakSample `json:"samples"`
}

type SoakMetricSampler interface {
	CaptureSoakMetrics(projectionLagHint int) (SoakMetricSnapshot, error)
}

type SoakMetricSource interface {
	SoakMetricSource() string
}

type SoakMetricSnapshot struct {
	DBPoolInUse         float64
	DBPoolSize          float64
	QueueRejects        float64
	SignerRestarts      float64
	ProjectionLagEvents float64
	OutboxLagItems      float64
	StorageBytes        float64
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
	sampler := opts.Sampler
	if sampler == nil {
		sampler = processSoakSampler{}
	}
	source := liveStackProfile
	if named, ok := sampler.(SoakMetricSource); ok {
		if s := named.SoakMetricSource(); s != "" {
			source = s
		}
	}
	ops, _, cleanup, err := liveServedOperations()
	if err != nil {
		return SoakSeries{}, err
	}
	defer cleanup()

	series := SoakSeries{
		Profile:     opts.Profile,
		Source:      source,
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
		sample, err := captureOneSoakSample(sampleTime, ops, opts.LoadSamples, sampler)
		if err != nil {
			return SoakSeries{}, err
		}
		series.Samples = append(series.Samples, sample)
	}
	return series, nil
}

func captureOneSoakSample(t time.Time, ops map[string]operation, loadSamples int, sampler SoakMetricSampler) (SoakSample, error) {
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
	metrics, err := sampler.CaptureSoakMetrics(projectionLag)
	if err != nil {
		return SoakSample{}, err
	}
	if metrics.ProjectionLagEvents < float64(projectionLag) {
		metrics.ProjectionLagEvents = float64(projectionLag)
	}
	if metrics.StorageBytes <= 0 {
		metrics.StorageBytes = float64(rm.HeapInuseBytes + rm.StackInuseBytes)
	}
	return SoakSample{
		T:                   t,
		RSSBytes:            float64(rm.MemorySysBytes),
		HeapBytes:           float64(rm.HeapInuseBytes),
		Goroutines:          float64(rm.Goroutines),
		OpenFDs:             float64(rm.OpenFDs),
		DBPoolInUse:         metrics.DBPoolInUse,
		DBPoolSize:          metrics.DBPoolSize,
		QueueRejects:        metrics.QueueRejects,
		SignerRestarts:      metrics.SignerRestarts,
		ProjectionLagEvents: metrics.ProjectionLagEvents,
		OutboxLagItems:      metrics.OutboxLagItems,
		StorageBytes:        metrics.StorageBytes,
		P95MS:               p95,
		P99MS:               p99,
	}, nil
}

type processSoakSampler struct{}

func (processSoakSampler) CaptureSoakMetrics(projectionLagHint int) (SoakMetricSnapshot, error) {
	rm := captureResourceMetrics(projectionLagHint)
	return SoakMetricSnapshot{
		ProjectionLagEvents: float64(projectionLagHint),
		StorageBytes:        float64(rm.HeapInuseBytes + rm.StackInuseBytes),
	}, nil
}
