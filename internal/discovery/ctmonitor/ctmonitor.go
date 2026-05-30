// Package ctmonitor watches Certificate Transparency logs (RFC 6962) for
// certificates issued for an organization's domains and raises an alert on any
// it did not expect — shadow IT, a rogue CA, or a compromised internal issuer
// (F17). It is the network watcher half of CT monitoring; certificate parsing
// stays behind the crypto boundary (internal/crypto/ctlog), so this package
// imports no crypto.
//
// Each log is polled incrementally from a checkpoint (the next tree index to
// read). Certificates whose names match a watched domain and that are not
// already known to the inventory are reported as Findings and raised on the
// shared notification surface (notify.DestinationCTLog), the same surface
// expiration alerts use. Polling multiple logs is bounded by a worker pool
// (AN-7).
package ctmonitor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"certctl.io/certctl/internal/bulkhead"
	"certctl.io/certctl/internal/crypto/ctlog"
)

// defaultMaxBatch bounds how many entries a single Poll reads from a log.
const defaultMaxBatch = 256

// LogState is a CT log and how far it has been read. Checkpoint is the next tree
// index to fetch; callers persist it between polls.
type LogState struct {
	URL        string
	Checkpoint int64
}

// Finding is one unexpected certificate observed in a CT log.
type Finding struct {
	LogURL        string
	Index         int64
	Subject       string
	Issuer        string
	Serial        string
	Fingerprint   string
	DNSNames      []string
	NotAfter      time.Time
	MatchedDomain string
}

// Fetcher reads RFC 6962 logs. Entries returns the entries in [start, end).
type Fetcher interface {
	TreeSize(ctx context.Context, logURL string) (int64, error)
	Entries(ctx context.Context, logURL string, start, end int64) ([]ctlog.Entry, error)
}

// KnownGood decides whether a logged certificate is expected (already known to
// the inventory or otherwise sanctioned), in which case it raises no alert.
type KnownGood interface {
	IsKnown(ctx context.Context, tenantID string, e ctlog.Entry) (bool, error)
}

// KnownGoodFunc adapts a function to KnownGood.
type KnownGoodFunc func(ctx context.Context, tenantID string, e ctlog.Entry) (bool, error)

// IsKnown calls f.
func (f KnownGoodFunc) IsKnown(ctx context.Context, tenantID string, e ctlog.Entry) (bool, error) {
	return f(ctx, tenantID, e)
}

// Alerter receives a Finding for an unexpected certificate and surfaces it.
type Alerter interface {
	Raise(ctx context.Context, tenantID string, f Finding) error
}

// MemoryAlerter records raised findings in memory; used in tests.
type MemoryAlerter struct {
	mu     sync.Mutex
	raised []Finding
}

// NewMemoryAlerter returns an empty in-memory alerter.
func NewMemoryAlerter() *MemoryAlerter { return &MemoryAlerter{} }

// Raise records the finding.
func (a *MemoryAlerter) Raise(_ context.Context, _ string, f Finding) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.raised = append(a.raised, f)
	return nil
}

// Raised returns a copy of the findings raised so far.
func (a *MemoryAlerter) Raised() []Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Finding, len(a.raised))
	copy(out, a.raised)
	return out
}

// Config configures a Monitor.
type Config struct {
	WatchedDomains []string // organization domains to watch; subdomains match
	MaxBatch       int      // max entries per Poll (default 256)
}

// Option configures a Monitor.
type Option func(*Monitor)

// WithWorkers sets the concurrency of PollAll across logs (default 8).
func WithWorkers(n int) Option {
	return func(m *Monitor) {
		if n > 0 {
			m.workers = n
		}
	}
}

// WithQueue sets PollAll's bounded queue depth (default 64).
func WithQueue(n int) Option {
	return func(m *Monitor) {
		if n >= 0 {
			m.queue = n
		}
	}
}

// WithBackoff sets the wait before retrying a back-pressured submission.
func WithBackoff(d time.Duration) Option {
	return func(m *Monitor) {
		if d > 0 {
			m.backoff = d
		}
	}
}

// Monitor watches CT logs and raises alerts on unexpected issuance.
type Monitor struct {
	fetch   Fetcher
	known   KnownGood
	alert   Alerter
	cfg     Config
	workers int
	queue   int
	backoff time.Duration
}

// New builds a Monitor over the given fetcher, known-good check, and alerter.
func New(fetch Fetcher, known KnownGood, alert Alerter, cfg Config, opts ...Option) *Monitor {
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = defaultMaxBatch
	}
	m := &Monitor{
		fetch: fetch, known: known, alert: alert, cfg: cfg,
		workers: 8, queue: 64, backoff: 5 * time.Millisecond,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Poll reads the new entries of one log since its checkpoint, raises an alert on
// each unexpected certificate for a watched domain, and returns the advanced log
// state and the findings. It reads at most Config.MaxBatch entries per call, so
// a backlog is drained over successive polls.
func (m *Monitor) Poll(ctx context.Context, tenantID string, log LogState) (LogState, []Finding, error) {
	size, err := m.fetch.TreeSize(ctx, log.URL)
	if err != nil {
		return log, nil, err
	}
	start := log.Checkpoint
	if start < 0 {
		start = 0
	}
	if size <= start {
		return LogState{URL: log.URL, Checkpoint: start}, nil, nil
	}
	end := size
	if end-start > int64(m.cfg.MaxBatch) {
		end = start + int64(m.cfg.MaxBatch)
	}

	entries, err := m.fetch.Entries(ctx, log.URL, start, end)
	if err != nil {
		return log, nil, err
	}

	var findings []Finding
	for _, e := range entries {
		domain, ok := matchWatched(e.DNSNames, m.cfg.WatchedDomains)
		if !ok {
			continue
		}
		known, err := m.known.IsKnown(ctx, tenantID, e)
		if err != nil {
			return log, nil, err
		}
		if known {
			continue
		}
		f := Finding{
			LogURL: log.URL, Index: e.Index, Subject: e.Subject, Issuer: e.Issuer,
			Serial: e.SerialHex, Fingerprint: e.FingerprintSHA256, DNSNames: e.DNSNames,
			NotAfter: e.NotAfter, MatchedDomain: domain,
		}
		if err := m.alert.Raise(ctx, tenantID, f); err != nil {
			return log, nil, err
		}
		findings = append(findings, f)
	}
	return LogState{URL: log.URL, Checkpoint: end}, findings, nil
}

// PollAll polls every log on a bounded worker pool (AN-7) and returns the
// advanced states (in the input order) and the aggregated findings. The first
// error from any log is returned.
func (m *Monitor) PollAll(ctx context.Context, tenantID string, logs []LogState) ([]LogState, []Finding, error) {
	pool := bulkhead.New(bulkhead.Config{Name: "ct-monitor", Workers: m.workers, Queue: m.queue})
	defer pool.Close()

	states := make([]LogState, len(logs))
	results := make([][]Finding, len(logs))
	errs := make([]error, len(logs))

	var wg sync.WaitGroup
	for i, lg := range logs {
		i, lg := i, lg
		wg.Add(1)
		task := func() {
			defer wg.Done()
			st, fs, err := m.Poll(ctx, tenantID, lg)
			states[i] = st
			results[i] = fs
			errs[i] = err
		}
		if err := m.submit(ctx, pool, task); err != nil {
			wg.Done()
			states[i] = lg
			errs[i] = err
		}
	}
	wg.Wait()

	var findings []Finding
	var firstErr error
	for i := range logs {
		if errs[i] != nil && firstErr == nil {
			firstErr = errs[i]
		}
		findings = append(findings, results[i]...)
	}
	return states, findings, firstErr
}

// submit enqueues a task, waiting out backpressure rather than dropping a log.
func (m *Monitor) submit(ctx context.Context, pool *bulkhead.Pool, task func()) error {
	for {
		err := pool.Submit(task)
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
		case <-time.After(m.backoff):
		}
	}
}

// matchWatched returns the first watched domain a certificate's names cover.
func matchWatched(dnsNames, watched []string) (string, bool) {
	for _, d := range watched {
		for _, name := range dnsNames {
			if DomainMatch(name, d) {
				return d, true
			}
		}
	}
	return "", false
}

// DomainMatch reports whether a certificate DNS name falls under a watched
// domain: an exact match, a subdomain, or a wildcard covering the domain.
// Matching is case-insensitive and resistant to the "example.com.evil.net"
// suffix trick.
func DomainMatch(certName, watched string) bool {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(certName), "."))
	w := strings.ToLower(strings.TrimSpace(watched))
	if name == "" || w == "" {
		return false
	}
	name = strings.TrimPrefix(name, "*.")
	return name == w || strings.HasSuffix(name, "."+w)
}
