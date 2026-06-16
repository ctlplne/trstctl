// Package cloudcert discovers certificates directly through cloud-provider APIs
// — AWS ACM, Azure Key Vault, GCP Certificate Manager — without a
// network-reachable handshake or an installed agent (F49). It closes the
// discovery blind spot where scans cannot reach a cloud workload and agents
// cannot run on a managed service.
//
// Discovery is strictly read-only: a Provider lists and describes certificates,
// never mutating the cloud account. Certificate parsing routes through the
// crypto boundary (certinfo); this package and the per-provider enumerators
// import no crypto/*. The Discoverer runs providers on a bounded worker pool
// (AN-7), and provider HTTP calls back off on rate limits (see Fetch).
package cloudcert

import (
	"context"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Found is a certificate discovered through a cloud-provider API.
type Found struct {
	Provider   string        // e.g. aws-acm, azure-keyvault, gcp-certmanager
	ResourceID string        // ARN / Key Vault id / GCP resource name
	Location   string        // region / vault host / project-location
	Cert       certinfo.Info // the certificate's inventory metadata
}

// Sink receives discovered certificates for merge into the inventory.
type Sink interface {
	Record(ctx context.Context, f Found) error
}

// MemorySink collects discoveries in memory; used in tests.
type MemorySink struct {
	mu    sync.Mutex
	items []Found
}

// NewMemorySink returns an empty in-memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Record stores the discovery.
func (m *MemorySink) Record(_ context.Context, f Found) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, f)
	return nil
}

// All returns a copy of the recorded discoveries.
func (m *MemorySink) All() []Found {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Found, len(m.items))
	copy(out, m.items)
	return out
}

// Provider enumerates certificates from one cloud account/service, read-only.
type Provider interface {
	Name() string
	Enumerate(ctx context.Context) ([]Found, error)
}

// Report summarizes a discovery pass.
type Report struct {
	Providers  int
	Discovered int
	Failed     int // providers that returned an error
}

type config struct {
	workers int
	queue   int
	backoff time.Duration
}

// Option configures a Discoverer.
type Option func(*config)

// WithWorkers sets the maximum number of providers enumerated concurrently.
func WithWorkers(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.workers = n
		}
	}
}

// WithQueue sets the bounded submission queue depth.
func WithQueue(n int) Option {
	return func(c *config) {
		if n >= 0 {
			c.queue = n
		}
	}
}

// WithBackoff sets the wait before retrying a back-pressured submission.
func WithBackoff(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.backoff = d
		}
	}
}

// Discoverer enumerates a set of providers on a bounded pool and records every
// certificate to the sink.
type Discoverer struct {
	sink    Sink
	pool    *bulkhead.Pool
	backoff time.Duration
}

// NewDiscoverer builds a Discoverer recording to sink.
func NewDiscoverer(sink Sink, opts ...Option) *Discoverer {
	cfg := config{workers: 4, queue: 64, backoff: 5 * time.Millisecond}
	for _, o := range opts {
		o(&cfg)
	}
	return &Discoverer{
		sink:    sink,
		pool:    bulkhead.New(bulkhead.Config{Name: "cloud-discovery", Workers: cfg.workers, Queue: cfg.queue}),
		backoff: cfg.backoff,
	}
}

// Close shuts the pool down.
func (d *Discoverer) Close() { d.pool.Close() }

// Discover enumerates every provider, bounded by the pool, recording each
// certificate to the sink. A provider error is counted, not fatal: the others'
// results are still recorded.
func (d *Discoverer) Discover(ctx context.Context, providers []Provider) Report {
	rep := Report{Providers: len(providers)}
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for _, p := range providers {
		p := p
		wg.Add(1)
		task := func() {
			defer wg.Done()
			found, err := p.Enumerate(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				rep.Failed++
				return
			}
			for _, f := range found {
				if err := d.sink.Record(ctx, f); err != nil {
					rep.Failed++
					return
				}
				rep.Discovered++
			}
		}
		if err := d.submit(ctx, task); err != nil {
			wg.Done()
			mu.Lock()
			rep.Failed++
			mu.Unlock()
		}
	}
	wg.Wait()
	return rep
}

// submit enqueues a task, waiting out backpressure rather than dropping a
// provider.
func (d *Discoverer) submit(ctx context.Context, task func()) error {
	for {
		err := d.pool.Submit(task)
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
		case <-time.After(d.backoff):
		}
	}
}
