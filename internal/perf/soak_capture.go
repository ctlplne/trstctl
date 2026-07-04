// SPDX-License-Identifier: MPL-2.0

package perf

import (
	"context"
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

type SoakSampleNormalizer interface {
	NormalizeSoakSample(SoakSample) SoakSample
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	stack, err := startLiveEvalStack(ctx)
	if err != nil {
		return SoakSeries{}, err
	}
	defer stack.Close()
	ops, _, err := stack.servedHotPaths()
	if err != nil {
		return SoakSeries{}, err
	}

	series := SoakSeries{
		Profile:     opts.Profile,
		Source:      source,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Samples:     make([]SoakSample, 0, opts.Samples),
	}
	start := time.Now().UTC()
	var queueRejectsTotal float64
	for i := 0; i < opts.Samples; i++ {
		if i > 0 && opts.Sleep {
			time.Sleep(opts.Step)
		}
		sampleTime := start.Add(time.Duration(i) * opts.Step)
		if opts.Sleep {
			sampleTime = time.Now().UTC()
		}
		sample, queueRejects, err := captureOneSoakSample(sampleTime, ops, opts.LoadSamples, sampler)
		if err != nil {
			return SoakSeries{}, err
		}
		queueRejectsTotal += queueRejects
		if sample.QueueRejects < queueRejectsTotal {
			sample.QueueRejects = queueRejectsTotal
		}
		series.Samples = append(series.Samples, sample)
	}
	return series, nil
}

func captureOneSoakSample(t time.Time, ops map[string]operation, loadSamples int, sampler SoakMetricSampler) (SoakSample, float64, error) {
	phase, err := StartBoundedRejectionPhase()
	if err != nil {
		return SoakSample{}, 0, err
	}
	defer phase.Close()

	var p95, p99 float64
	var projectionLag int
	for _, slo := range HotPaths() {
		op, ok := ops[slo.HotPath]
		if !ok {
			return SoakSample{}, 0, fmt.Errorf("perf soak capture: no operation for hot path %s", slo.HotPath)
		}
		result := measure(slo, op, loadSamples, Observation{})
		if result.Errors > 0 {
			return SoakSample{}, 0, fmt.Errorf("perf soak capture: %s produced %d errors: %v", slo.HotPath, result.Errors, result.Failures)
		}
		p95 = math.Max(p95, result.P95MS)
		p99 = math.Max(p99, result.P99MS)
		if result.ProjectionLagEvents > projectionLag {
			projectionLag = result.ProjectionLagEvents
		}
	}
	rm := captureResourceMetrics(projectionLag)
	if observer, ok := sampler.(SoakBackpressureObserver); ok {
		observer.ObserveSoakBackpressure(phase.Stats())
	}
	metrics, err := sampler.CaptureSoakMetrics(projectionLag)
	if err != nil {
		return SoakSample{}, 0, err
	}
	queueRejects := phase.QueueRejects()
	if metrics.QueueRejects < queueRejects {
		metrics.QueueRejects = queueRejects
	}
	if metrics.ProjectionLagEvents < float64(projectionLag) {
		metrics.ProjectionLagEvents = float64(projectionLag)
	}
	if metrics.StorageBytes <= 0 {
		metrics.StorageBytes = float64(rm.HeapInuseBytes + rm.StackInuseBytes)
	}
	sample := SoakSample{
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
	}
	if normalizer, ok := sampler.(SoakSampleNormalizer); ok {
		sample = normalizer.NormalizeSoakSample(sample)
	}
	return sample, queueRejects, nil
}

type processSoakSampler struct{}

func (processSoakSampler) CaptureSoakMetrics(projectionLagHint int) (SoakMetricSnapshot, error) {
	rm := captureResourceMetrics(projectionLagHint)
	return SoakMetricSnapshot{
		ProjectionLagEvents: float64(projectionLagHint),
		StorageBytes:        float64(rm.HeapInuseBytes + rm.StackInuseBytes),
	}, nil
}
