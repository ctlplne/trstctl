package perf

import (
	"testing"
	"time"
)

func TestCaptureSoakSeriesFeedsAnalyzer(t *testing.T) {
	series, err := CaptureSoakSeries(SoakCaptureOptions{
		Profile:     "captured-soak-test",
		Samples:     3,
		Step:        time.Minute,
		LoadSamples: 4,
		Sleep:       false,
		Sampler: fixedSoakSampler{
			snapshot: SoakMetricSnapshot{
				DBPoolInUse:         2,
				DBPoolSize:          16,
				ProjectionLagEvents: 3,
				OutboxLagItems:      4,
				StorageBytes:        32 * 1024 * 1024,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if series.Profile != "captured-soak-test" || series.Source != liveStackProfile {
		t.Fatalf("bad series metadata: %+v", series)
	}
	if len(series.Samples) != 3 {
		t.Fatalf("captured samples = %d, want 3", len(series.Samples))
	}
	for i, sample := range series.Samples {
		if sample.T.IsZero() {
			t.Fatalf("sample %d has zero timestamp", i)
		}
		if sample.P95MS <= 0 || sample.P99MS <= 0 {
			t.Fatalf("sample %d missing latency capture: %+v", i, sample)
		}
		if sample.RSSBytes <= 0 || sample.HeapBytes <= 0 || sample.Goroutines <= 0 || sample.OpenFDs <= 0 {
			t.Fatalf("sample %d missing resource capture: %+v", i, sample)
		}
		if sample.DBPoolSize <= 0 {
			t.Fatalf("sample %d missing DB pool denominator: %+v", i, sample)
		}
		if sample.DBPoolSize != 16 || sample.OutboxLagItems != 4 || sample.ProjectionLagEvents != 3 || sample.StorageBytes != 32*1024*1024 {
			t.Fatalf("sample %d did not use live sampler metrics: %+v", i, sample)
		}
	}
	report, err := AnalyzeSoak(series.Profile, series.Samples, DefaultSoakThresholds())
	if err != nil {
		t.Fatalf("AnalyzeSoak(captured): %v", err)
	}
	if !report.Summary.OK {
		t.Fatalf("captured live-stack soak series should pass default thresholds: %+v", report.Summary)
	}
}

type fixedSoakSampler struct {
	snapshot SoakMetricSnapshot
}

func (s fixedSoakSampler) CaptureSoakMetrics(int) (SoakMetricSnapshot, error) {
	return s.snapshot, nil
}
