// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"context"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
)

// Source enumerates cryptographic observations from one part of the environment
// (TLS endpoints, host config, ...). Sources are read-only and non-invasive.
type Source interface {
	Name() string
	Scan(ctx context.Context) ([]Finding, error)
}

// PartialScanError reports input-level failures while preserving successful
// findings from the same source. This keeps a mixed run useful without turning
// an unreachable endpoint or unreadable file into silent success.
type PartialScanError struct {
	Failures int
	Err      error
}

func (e *PartialScanError) Error() string {
	if e == nil || e.Err == nil {
		return "CBOM source partially failed"
	}
	return e.Err.Error()
}

func (e *PartialScanError) Unwrap() error { return e.Err }

// Sink receives classified findings for the CBOM.
type Sink interface {
	Record(ctx context.Context, f Finding) error
}

// MemorySink collects findings in memory; used in tests.
type MemorySink struct {
	mu    sync.Mutex
	items []Finding
}

// NewMemorySink returns an empty in-memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Record stores the finding.
func (m *MemorySink) Record(_ context.Context, f Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, f)
	return nil
}

// All returns a copy of the recorded findings.
func (m *MemorySink) All() []Finding {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Finding, len(m.items))
	copy(out, m.items)
	return out
}

// Report summarizes a scan.
type Report struct {
	Sources           int
	Findings          int
	Weak              int
	QuantumVulnerable int
	OutOfPolicy       int
	Failed            int // source scans or individual finding records that errored
}

type scanConfig struct {
	policy               Policy
	workers              int
	queue                int
	backoff              time.Duration
	maxFindingsPerSource int
}

// DefaultMaxFindingsPerSource is the hard write-amplification ceiling for one
// source. A source may inspect many declarations, but a single request can never
// turn into an unbounded number of event/projection writes.
const DefaultMaxFindingsPerSource = 1024

// Option configures a Scanner.
type Option func(*scanConfig)

// WithPolicy sets the classification policy (default DefaultPolicy).
func WithPolicy(p Policy) Option { return func(c *scanConfig) { c.policy = p } }

// WithWorkers bounds how many sources scan concurrently.
func WithWorkers(n int) Option {
	return func(c *scanConfig) {
		if n > 0 {
			c.workers = n
		}
	}
}

// WithQueue sets the bounded submission queue depth.
func WithQueue(n int) Option {
	return func(c *scanConfig) {
		if n >= 0 {
			c.queue = n
		}
	}
}

// WithBackoff sets the wait before retrying a back-pressured submission.
func WithBackoff(d time.Duration) Option {
	return func(c *scanConfig) {
		if d > 0 {
			c.backoff = d
		}
	}
}

// WithMaxFindingsPerSource bounds classified records emitted by each source.
func WithMaxFindingsPerSource(n int) Option {
	return func(c *scanConfig) {
		if n > 0 {
			c.maxFindingsPerSource = n
		}
	}
}

// Scanner runs sources on a bounded pool (AN-7), classifies each finding against
// the policy, and records it to the sink.
type Scanner struct {
	sink                 Sink
	policy               Policy
	pool                 *bulkhead.Pool
	backoff              time.Duration
	maxFindingsPerSource int
}

// NewScanner builds a Scanner recording to sink.
func NewScanner(sink Sink, opts ...Option) *Scanner {
	cfg := scanConfig{
		policy: DefaultPolicy(), workers: 4, queue: 64, backoff: 5 * time.Millisecond,
		maxFindingsPerSource: DefaultMaxFindingsPerSource,
	}
	for _, o := range opts {
		o(&cfg)
	}
	return &Scanner{
		sink:                 sink,
		policy:               cfg.policy,
		pool:                 bulkhead.New(bulkhead.Config{Name: "cbom-scan", Workers: cfg.workers, Queue: cfg.queue}),
		backoff:              cfg.backoff,
		maxFindingsPerSource: cfg.maxFindingsPerSource,
	}
}

// Close shuts the pool down.
func (s *Scanner) Close() { s.pool.Close() }

// Scan runs every source, classifies its findings, and records them. A source
// error is counted, not fatal.
func (s *Scanner) Scan(ctx context.Context, sources []Source) Report {
	rep := Report{Sources: len(sources)}
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for _, src := range sources {
		src := src
		wg.Add(1)
		task := func() {
			defer wg.Done()
			findings, err := src.Scan(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				var partial *PartialScanError
				if errors.As(err, &partial) && partial.Failures > 0 {
					rep.Failed += partial.Failures
				} else {
					rep.Failed++
				}
				if len(findings) == 0 {
					return
				}
			}
			if len(findings) > s.maxFindingsPerSource {
				findings = findings[:s.maxFindingsPerSource]
				rep.Failed++ // visible evidence that the source hit its safety ceiling
			}
			for _, f := range findings {
				f = f.Classified(s.policy)
				if err := s.sink.Record(ctx, f); err != nil {
					rep.Failed++
					// Findings are independent observations. A transient failure while
					// persisting one fact must not discard every later fact returned by
					// the same source; keep the failure visible in the report and attempt
					// the remaining observations.
					continue
				}
				rep.Findings++
				if f.Class.Strength == StrengthWeak {
					rep.Weak++
				}
				if f.Class.QuantumVulnerable {
					rep.QuantumVulnerable++
				}
				if f.Class.OutOfPolicy {
					rep.OutOfPolicy++
				}
			}
		}
		if err := s.submit(ctx, task); err != nil {
			wg.Done()
			mu.Lock()
			rep.Failed++
			mu.Unlock()
		}
	}
	wg.Wait()
	return rep
}

func (s *Scanner) submit(ctx context.Context, task func()) error {
	for {
		err := s.pool.Submit(task)
		if err == nil {
			return nil
		}
		var rj *bulkhead.Rejected
		if !errors.As(err, &rj) || !rj.Retryable() {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.backoff):
		}
	}
}
