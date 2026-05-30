// Package netscan discovers certificates by non-invasive TLS handshakes over
// operator-defined IP/port ranges (F2, S6.1). It runs on its own bounded worker
// pool (AN-7): concurrency is capped and the producer is throttled by
// backpressure, so a scan can neither flood the host nor starve another
// subsystem (for example the API), which has its own isolated pool.
//
// Each probe is a non-invasive TLS handshake (internal/crypto/tlsprobe) that
// captures the presented certificate; the metadata is extracted through the
// crypto boundary (internal/crypto/certinfo) and merged into the inventory via a
// Sink. The package imports no crypto/* — the handshake and parsing live behind
// the boundary.
package netscan

import (
	"context"
	"errors"
	"sync"
	"time"

	"certctl.io/certctl/internal/bulkhead"
	"certctl.io/certctl/internal/crypto/certinfo"
	"certctl.io/certctl/internal/crypto/tlsprobe"
)

// Found is a certificate discovered at a network address.
type Found struct {
	Address string        // the host:port it was served from
	Cert    certinfo.Info // the leaf certificate's inventory metadata
}

// Sink receives discovered certificates for merge into the inventory. Production
// wires StoreSink (an idempotent upsert by fingerprint); tests use MemorySink.
type Sink interface {
	Record(ctx context.Context, f Found) error
}

// Prober captures the leaf certificate served at addr. The default composes the
// TLS handshake and the metadata extraction through the crypto boundary; tests
// inject a fake.
type Prober func(ctx context.Context, addr string) (certinfo.Info, error)

// DefaultProber performs a non-invasive TLS handshake and returns the presented
// leaf certificate's metadata.
func DefaultProber(ctx context.Context, addr string) (certinfo.Info, error) {
	res, err := tlsprobe.Probe(ctx, addr)
	if err != nil {
		return certinfo.Info{}, err
	}
	return certinfo.Inspect(res.PeerCertificates[0])
}

// Report summarizes a scan.
type Report struct {
	Targets    int // addresses submitted
	Discovered int // certificates found and recorded
	Failed     int // probe errors (unreachable, no TLS, sink error)
	Rejected   int // could not be submitted (pool closed or context cancelled)
}

type config struct {
	prober  Prober
	workers int
	queue   int
	backoff time.Duration
}

// Option configures a Scanner.
type Option func(*config)

// WithProber overrides the probe function (tests).
func WithProber(p Prober) Option {
	return func(c *config) {
		if p != nil {
			c.prober = p
		}
	}
}

// WithWorkers sets the maximum number of concurrent handshakes (default 16).
func WithWorkers(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.workers = n
		}
	}
}

// WithQueue sets the bounded queue depth in front of the workers (default 256).
func WithQueue(n int) Option {
	return func(c *config) {
		if n >= 0 {
			c.queue = n
		}
	}
}

// WithBackoff sets how long the scanner waits before retrying a submission the
// pool rejected for backpressure (default 5ms).
func WithBackoff(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.backoff = d
		}
	}
}

// Scanner discovers certificates over network ranges using a bounded pool.
type Scanner struct {
	sink    Sink
	prober  Prober
	pool    *bulkhead.Pool
	backoff time.Duration
}

// New builds a Scanner that records discoveries to sink.
func New(sink Sink, opts ...Option) *Scanner {
	cfg := config{prober: DefaultProber, workers: 16, queue: 256, backoff: 5 * time.Millisecond}
	for _, o := range opts {
		o(&cfg)
	}
	return &Scanner{
		sink:    sink,
		prober:  cfg.prober,
		pool:    bulkhead.New(bulkhead.Config{Name: "network-scan", Workers: cfg.workers, Queue: cfg.queue}),
		backoff: cfg.backoff,
	}
}

// Close drains in-flight probes and shuts the pool down.
func (s *Scanner) Close() { s.pool.Close() }

// Stats exposes the pool's bounded capacity and counters.
func (s *Scanner) Stats() bulkhead.Stats { return s.pool.Stats() }

// Scan probes each target, recording every certificate it discovers. Work is
// bounded by the pool's workers; when the queue is full the producer is throttled
// (backpressure) rather than dropping targets, so every reachable target is
// scanned. Scan blocks until all submitted probes complete.
func (s *Scanner) Scan(ctx context.Context, targets []string) Report {
	rep := Report{Targets: len(targets)}
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, addr := range targets {
		if ctx.Err() != nil {
			mu.Lock()
			rep.Rejected++
			mu.Unlock()
			continue
		}
		addr := addr
		wg.Add(1)
		task := func() {
			defer wg.Done()
			info, err := s.prober(ctx, addr)
			if err == nil {
				err = s.sink.Record(ctx, Found{Address: addr, Cert: info})
			}
			mu.Lock()
			if err != nil {
				rep.Failed++
			} else {
				rep.Discovered++
			}
			mu.Unlock()
		}
		if err := s.submit(ctx, task); err != nil {
			wg.Done()
			mu.Lock()
			rep.Rejected++
			mu.Unlock()
		}
	}

	wg.Wait()
	return rep
}

// submit enqueues task, throttling on backpressure: a retryable rejection (full
// queue) is retried after a backoff, so no target is dropped just because the
// pool is momentarily saturated. A permanent rejection (closed pool) or a
// cancelled context returns an error.
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

// MemorySink records discoveries in memory for tests.
type MemorySink struct {
	mu    sync.Mutex
	found []Found
}

var _ Sink = (*MemorySink)(nil)

// NewMemorySink returns an empty in-memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Record stores the discovery.
func (m *MemorySink) Record(_ context.Context, f Found) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.found = append(m.found, f)
	return nil
}

// All returns the discoveries recorded so far.
func (m *MemorySink) All() []Found {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Found, len(m.found))
	copy(out, m.found)
	return out
}
