// Package sshscan discovers SSH host keys by non-invasive SSH handshakes over
// operator-defined ranges (F2/F42, S6.3) — the SSH counterpart of
// internal/discovery/netscan. It runs on its own bounded worker pool (AN-7):
// concurrency is capped and the producer is throttled by backpressure, so a scan
// can neither flood the host nor starve another subsystem. Targets are
// host:port; netscan.ExpandRange turns CIDR ranges into them.
//
// Each probe captures the server's host key through the crypto boundary
// (internal/crypto/sshprobe); this package imports no crypto.
package sshscan

import (
	"context"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto/sshprobe"
	"trstctl.com/trstctl/internal/sshinv"
)

// Prober captures the host key served at addr. The default uses the crypto
// boundary's non-invasive SSH probe; tests inject a fake.
type Prober func(ctx context.Context, addr string) (sshinv.Found, error)

// DefaultProber performs a non-invasive SSH handshake and returns the host key.
func DefaultProber(ctx context.Context, addr string) (sshinv.Found, error) {
	res, err := sshprobe.Probe(ctx, addr)
	if err != nil {
		return sshinv.Found{}, err
	}
	return sshinv.Found{
		Source:      sshinv.SourceHostProbe,
		Location:    addr,
		KeyType:     res.HostKeyType,
		Fingerprint: res.FingerprintSHA256,
	}, nil
}

// Report summarizes a scan.
type Report struct {
	Targets    int
	Discovered int
	Failed     int
	Rejected   int
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

// WithQueue sets the bounded queue depth (default 256).
func WithQueue(n int) Option {
	return func(c *config) {
		if n >= 0 {
			c.queue = n
		}
	}
}

// WithBackoff sets the wait before retrying a back-pressured submission
// (default 5ms).
func WithBackoff(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.backoff = d
		}
	}
}

// Scanner discovers SSH host keys over network ranges using a bounded pool.
type Scanner struct {
	sink    sshinv.Sink
	prober  Prober
	pool    *bulkhead.Pool
	backoff time.Duration
}

// New builds a Scanner that records discoveries to sink.
func New(sink sshinv.Sink, opts ...Option) *Scanner {
	cfg := config{prober: DefaultProber, workers: 16, queue: 256, backoff: 5 * time.Millisecond}
	for _, o := range opts {
		o(&cfg)
	}
	return &Scanner{
		sink:    sink,
		prober:  cfg.prober,
		pool:    bulkhead.New(bulkhead.Config{Name: "ssh-scan", Workers: cfg.workers, Queue: cfg.queue}),
		backoff: cfg.backoff,
	}
}

// Close drains in-flight probes and shuts the pool down.
func (s *Scanner) Close() { s.pool.Close() }

// Stats exposes the pool's bounded capacity and counters.
func (s *Scanner) Stats() bulkhead.Stats { return s.pool.Stats() }

// Scan probes each target, recording every host key it discovers. Work is bounded
// by the pool's workers; a full queue throttles the producer rather than dropping
// targets. Scan blocks until all submitted probes complete.
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
			found, err := s.prober(ctx, addr)
			if err == nil {
				err = s.sink.Record(ctx, found)
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
