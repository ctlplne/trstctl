// SPDX-License-Identifier: BUSL-1.1

package cbom_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cbom"
)

type fakeSource struct {
	name     string
	findings []cbom.Finding
	err      error
	delay    time.Duration
	current  *atomic.Int32
	peak     *atomic.Int32
}

type failOnceSink struct {
	failed bool
	items  []cbom.Finding
}

func (s *failOnceSink) Record(_ context.Context, finding cbom.Finding) error {
	if !s.failed {
		s.failed = true
		return errors.New("transient persistence failure")
	}
	s.items = append(s.items, finding)
	return nil
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Scan(context.Context) ([]cbom.Finding, error) {
	if f.current != nil {
		c := f.current.Add(1)
		for {
			pk := f.peak.Load()
			if c <= pk || f.peak.CompareAndSwap(pk, c) {
				break
			}
		}
		defer f.current.Add(-1)
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.findings, f.err
}

func TestScannerClassifiesAndRecords(t *testing.T) {
	sink := cbom.NewMemorySink()
	sc := cbom.NewScanner(sink)
	defer sc.Close()

	sources := []cbom.Source{
		&fakeSource{name: "a", findings: []cbom.Finding{
			{Kind: cbom.AssetCertKey, Location: "h:443", Algorithm: "RSA", KeyBits: 1024},
			{Kind: cbom.AssetTLSEndpoint, Location: "h:443", Protocol: "TLSv1.3"},
		}},
		&fakeSource{name: "b", findings: []cbom.Finding{
			{Kind: cbom.AssetTLSEndpoint, Location: "g:443", Protocol: "TLSv1.0"},
		}},
	}
	rep := sc.Scan(context.Background(), sources)

	if rep.Findings != 3 {
		t.Errorf("Findings = %d, want 3", rep.Findings)
	}
	if rep.Weak < 2 { // RSA-1024 and TLSv1.0
		t.Errorf("Weak = %d, want >= 2", rep.Weak)
	}
	if rep.QuantumVulnerable < 1 { // RSA-1024
		t.Errorf("QuantumVulnerable = %d, want >= 1", rep.QuantumVulnerable)
	}
	if rep.OutOfPolicy < 2 {
		t.Errorf("OutOfPolicy = %d, want >= 2", rep.OutOfPolicy)
	}
	for _, f := range sink.All() {
		if f.Class.Strength == "" {
			t.Errorf("recorded finding not classified: %+v", f)
		}
	}
}

func TestScannerCountsSourceFailures(t *testing.T) {
	sink := cbom.NewMemorySink()
	sc := cbom.NewScanner(sink)
	defer sc.Close()

	rep := sc.Scan(context.Background(), []cbom.Source{
		&fakeSource{name: "ok", findings: []cbom.Finding{{Kind: cbom.AssetTLSEndpoint, Protocol: "TLSv1.2"}}},
		&fakeSource{name: "broken", err: errors.New("boom")},
	})
	if rep.Findings != 1 || rep.Failed != 1 {
		t.Errorf("report = %+v, want 1 finding / 1 failed", rep)
	}
}

func TestScannerKeepsPartialFindingsAndCountsInputFailures(t *testing.T) {
	sink := cbom.NewMemorySink()
	sc := cbom.NewScanner(sink)
	defer sc.Close()

	rep := sc.Scan(context.Background(), []cbom.Source{
		&fakeSource{
			name:     "mixed",
			findings: []cbom.Finding{{Kind: cbom.AssetTLSEndpoint, Protocol: "TLSv1.2"}},
			err:      &cbom.PartialScanError{Failures: 2, Err: errors.New("two endpoints unreachable")},
		},
	})
	if rep.Findings != 1 || rep.Failed != 2 || len(sink.All()) != 1 {
		t.Fatalf("partial report = %+v sink=%+v, want one kept finding and two failures", rep, sink.All())
	}
}

func TestScannerCapsWritesPerSource(t *testing.T) {
	sink := cbom.NewMemorySink()
	sc := cbom.NewScanner(sink, cbom.WithMaxFindingsPerSource(2))
	defer sc.Close()

	rep := sc.Scan(context.Background(), []cbom.Source{
		&fakeSource{name: "large", findings: []cbom.Finding{
			{Kind: cbom.AssetTLSEndpoint, Protocol: "TLSv1.2"},
			{Kind: cbom.AssetTLSEndpoint, Protocol: "TLSv1.3"},
			{Kind: cbom.AssetTLSEndpoint, Protocol: "TLSv1.0"},
		}},
	})
	if rep.Findings != 2 || rep.Failed != 1 || len(sink.All()) != 2 {
		t.Fatalf("capped report = %+v sink=%+v, want two writes and one visible cap failure", rep, sink.All())
	}
}

func TestScannerContinuesAfterFindingRecordFailure(t *testing.T) {
	sink := &failOnceSink{}
	sc := cbom.NewScanner(sink)
	defer sc.Close()

	rep := sc.Scan(context.Background(), []cbom.Source{
		&fakeSource{name: "host-config", findings: []cbom.Finding{
			{Kind: cbom.AssetHostConfig, Protocol: "TLSv1.3"},
			{Kind: cbom.AssetHostConfig, Cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		}},
	})
	if rep.Findings != 1 || rep.Failed != 1 {
		t.Fatalf("report = %+v, want later finding recorded and one visible failure", rep)
	}
	if len(sink.items) != 1 || sink.items[0].Cipher != "TLS_RSA_WITH_3DES_EDE_CBC_SHA" || !sink.items[0].Class.OutOfPolicy {
		t.Fatalf("later independent finding was discarded: %+v", sink.items)
	}
}

func TestScannerBoundsConcurrency(t *testing.T) {
	const workers = 3
	var current, peak atomic.Int32
	var sources []cbom.Source
	for i := 0; i < 12; i++ {
		sources = append(sources, &fakeSource{
			name: fmt.Sprintf("s%d", i), delay: 5 * time.Millisecond,
			current: &current, peak: &peak,
			findings: []cbom.Finding{{Kind: cbom.AssetTLSEndpoint, Protocol: "TLSv1.2"}},
		})
	}
	sc := cbom.NewScanner(cbom.NewMemorySink(), cbom.WithWorkers(workers), cbom.WithQueue(100))
	defer sc.Close()

	rep := sc.Scan(context.Background(), sources)
	if rep.Findings != 12 {
		t.Errorf("Findings = %d, want 12", rep.Findings)
	}
	if peak.Load() > workers {
		t.Errorf("peak concurrency %d exceeded the %d-source bound", peak.Load(), workers)
	}
}
