// SPDX-License-Identifier: BUSL-1.1

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
	"fmt"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/crypto/weakkey"
	"trstctl.com/trstctl/internal/netsec"
)

// Found is a certificate discovered at a network address.
type Found struct {
	Address string        // the host:port it was served from
	Cert    certinfo.Info // the leaf certificate's inventory metadata
	Keys    KeyObservation
}

// KeyObservation is what the scanner's checks found on the served chain, as
// hashes and closed check codes (Part 4). LeafDER and ChainDER hold the
// certificates' public bytes; a sink keeps them only when its scan asked for
// them, so a certificate known only from a scan can have its revocation probed
// (A211). ChainDER[i] is the certificate ChainCertSHA256[i] names.
type KeyObservation struct {
	SPKISHA256      string
	AuthorityKeyID  string
	ChainSPKISHA256 []string
	ChainCertSHA256 []string
	WeakKeyChecks   []string
	LeafDER         []byte
	ChainDER        [][]byte
}

// Bounds on the public certificate bytes an observation holds.
const (
	MaxKeptCertificateBytes = 16 << 10
	MaxKeptIssuers          = 4
)

// ChainProber captures the served leaf and observes the served chain.
type ChainProber func(ctx context.Context, addr string) (certinfo.Info, KeyObservation, error)

// maxObservedIssuers bounds the served issuers described per target.
const maxObservedIssuers = 8

// DefaultChainProber is DefaultProber plus the observation of the served
// chain: the leaf's key hash and authority key identifier, each served
// issuer's key and certificate hashes, and the weak-key checks that fire on
// the leaf.
func DefaultChainProber(ctx context.Context, addr string) (certinfo.Info, KeyObservation, error) {
	return chainProbe(ctx, addr)
}

func chainProbe(ctx context.Context, addr string, opts ...tlsprobe.Option) (certinfo.Info, KeyObservation, error) {
	chain, err := probeChain(ctx, addr, opts...)
	if err != nil {
		return certinfo.Info{}, KeyObservation{}, err
	}
	info, err := certinfo.Inspect(chain[0])
	if err != nil {
		return certinfo.Info{}, KeyObservation{}, err
	}
	obs := KeyObservation{SPKISHA256: info.SPKISHA256, AuthorityKeyID: info.AuthorityKeyID}
	if len(chain[0]) <= MaxKeptCertificateBytes {
		obs.LeafDER = append([]byte(nil), chain[0]...)
	}
	for _, der := range chain[1:] {
		if len(obs.ChainSPKISHA256) == maxObservedIssuers {
			break
		}
		if issuer, err := certinfo.Inspect(der); err == nil {
			// Bytes stay a prefix of the hashes: once one issuer is not kept,
			// none after it is, so ChainDER[i] always matches ChainCertSHA256[i].
			if obs.LeafDER != nil && len(obs.ChainDER) == len(obs.ChainCertSHA256) &&
				len(obs.ChainDER) < MaxKeptIssuers && len(der) <= MaxKeptCertificateBytes {
				obs.ChainDER = append(obs.ChainDER, append([]byte(nil), der...))
			}
			obs.ChainSPKISHA256 = append(obs.ChainSPKISHA256, issuer.SPKISHA256)
			obs.ChainCertSHA256 = append(obs.ChainCertSHA256, issuer.SHA256Fingerprint)
		}
	}
	if findings, err := weakkey.Default().RateCertificate(chain[0]); err == nil {
		for _, f := range findings {
			obs.WeakKeyChecks = append(obs.WeakKeyChecks, f.Check)
		}
	}
	return info, obs, nil
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
	return leafProbe(ctx, addr)
}

func leafProbe(ctx context.Context, addr string, opts ...tlsprobe.Option) (certinfo.Info, error) {
	chain, err := probeChain(ctx, addr, opts...)
	if err != nil {
		return certinfo.Info{}, err
	}
	return certinfo.Inspect(chain[0])
}

// probeChain performs the handshake and returns the served chain, leaf first.
func probeChain(ctx context.Context, addr string, opts ...tlsprobe.Option) ([][]byte, error) {
	res, err := tlsprobe.Probe(ctx, addr, opts...)
	if err != nil {
		negotiated, retryErr := probeWithNegotiation(ctx, addr, err, opts...)
		if retryErr != nil {
			return nil, err
		}
		res = negotiated
	}
	if len(res.PeerCertificates) == 0 {
		return nil, errors.New("netscan: the listener presented no certificate")
	}
	return res.PeerCertificates, nil
}

// probeWithNegotiation retries a reachable listener that rejected a bare
// ClientHello with the application-level TLS negotiations the scanner knows
// (PostgreSQL's SSLRequest today). Unreachable targets are not retried.
func probeWithNegotiation(ctx context.Context, addr string, first error, opts ...tlsprobe.Option) (tlsprobe.Result, error) {
	var stage *tlsprobe.StageError
	if errors.As(first, &stage) && stage.Stage == tlsprobe.StageDial {
		return tlsprobe.Result{}, first
	}
	if ctx.Err() != nil {
		return tlsprobe.Result{}, first
	}
	return tlsprobe.Probe(ctx, addr, append(opts, tlsprobe.WithPreHandshake(tlsprobe.PostgresSSLRequest))...)
}

// Target outcome statuses carried in Report.TargetResults.
const (
	TargetSucceeded = "succeeded"
	TargetFailed    = "failed"
	TargetBlocked   = "blocked"
	TargetRejected  = "rejected"
	// TargetKindNetwork labels TLS listener probes in per-target results.
	TargetKindNetwork = "network"
)

// Report summarizes a scan.
type Report struct {
	Targets    int // addresses submitted
	Discovered int // certificates found and recorded
	Failed     int // probe errors (unreachable, no TLS, sink error)
	Rejected   int // could not be submitted (pool closed or context canceled)
	Blocked    int // skipped before dialing by the SSRF/reserved-address guard
	// TargetResults carries bounded per-target facts to the immutable run
	// completion event: one entry per submitted address (sorted by target) so a
	// partial run names which listener failed or was blocked and why. CT
	// monitoring fills it with its own kind and cursor.
	TargetResults []TargetResult
}

// TargetResult is one scanner target's terminal outcome.
type TargetResult struct {
	Kind   string
	Target string
	Status string
	Cursor int64
	Error  string
}

type config struct {
	prober        Prober
	chainProber   ChainProber
	injected      bool
	dialControl   func(network, address string, c syscall.RawConn) error
	workers       int
	queue         int
	backoff       time.Duration
	allowRFC1918  bool
	allowLoopback bool
	blockedHook   BlockedTargetHook
}

// Option configures a Scanner.
type Option func(*config)

// BlockedTarget is a target skipped before any network dial.
type BlockedTarget struct {
	Address string
	Reason  string
}

// BlockedTargetHook observes targets blocked by the SSRF/reserved-address guard.
type BlockedTargetHook func(context.Context, BlockedTarget)

// WithProber overrides the probe function (tests).
func WithProber(p Prober) Option {
	return func(c *config) {
		if p != nil {
			c.prober = p
			c.chainProber = nil
			c.injected = true
		}
	}
}

// WithChainProber injects a prober that also observes the served chain.
func WithChainProber(p ChainProber) Option {
	return func(c *config) {
		if p != nil {
			c.chainProber = p
			c.injected = true
		}
	}
}

// WithDialControl checks the resolved address of every handshake's dial, after
// the scanner's own target checks. It applies to the default probers only.
func WithDialControl(control func(network, address string, c syscall.RawConn) error) Option {
	return func(c *config) { c.dialControl = control }
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

// WithAllowRFC1918Targets permits RFC1918 targets while still blocking loopback,
// link-local metadata, multicast, unspecified, CGNAT, and IPv6 unique-local ranges.
func WithAllowRFC1918Targets(allow bool) Option {
	return func(c *config) {
		c.allowRFC1918 = allow
	}
}

// WithAllowLoopbackTargets permits loopback targets for tests and explicit
// localhost diagnostics. Production discovery should leave this false.
func WithAllowLoopbackTargets(allow bool) Option {
	return func(c *config) {
		c.allowLoopback = allow
	}
}

// WithBlockedTargetHook installs an audit hook for skipped reserved targets.
func WithBlockedTargetHook(h BlockedTargetHook) Option {
	return func(c *config) {
		c.blockedHook = h
	}
}

// Scanner discovers certificates over network ranges using a bounded pool.
type Scanner struct {
	sink          Sink
	prober        Prober
	chainProber   ChainProber
	pool          *bulkhead.Pool
	backoff       time.Duration
	allowRFC1918  bool
	allowLoopback bool
	blockedHook   BlockedTargetHook
}

// New builds a Scanner that records discoveries to sink.
func New(sink Sink, opts ...Option) *Scanner {
	cfg := config{prober: DefaultProber, chainProber: DefaultChainProber, workers: 16, queue: 256, backoff: 5 * time.Millisecond}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.dialControl != nil && !cfg.injected {
		dial := tlsprobe.WithDialControl(cfg.dialControl)
		cfg.prober = func(ctx context.Context, addr string) (certinfo.Info, error) { return leafProbe(ctx, addr, dial) }
		cfg.chainProber = func(ctx context.Context, addr string) (certinfo.Info, KeyObservation, error) {
			return chainProbe(ctx, addr, dial)
		}
	}
	return &Scanner{
		sink:          sink,
		prober:        cfg.prober,
		chainProber:   cfg.chainProber,
		pool:          bulkhead.New(bulkhead.Config{Name: "network-scan", Workers: cfg.workers, Queue: cfg.queue}),
		backoff:       cfg.backoff,
		allowRFC1918:  cfg.allowRFC1918,
		allowLoopback: cfg.allowLoopback,
		blockedHook:   cfg.blockedHook,
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
	rep := Report{Targets: len(targets), TargetResults: make([]TargetResult, 0, len(targets))}
	var wg sync.WaitGroup
	var mu sync.Mutex
	outcome := func(addr, status, detail string) {
		mu.Lock()
		defer mu.Unlock()
		switch status {
		case TargetSucceeded:
			rep.Discovered++
		case TargetFailed:
			rep.Failed++
		case TargetBlocked:
			rep.Blocked++
		case TargetRejected:
			rep.Rejected++
		}
		rep.TargetResults = append(rep.TargetResults, TargetResult{Kind: TargetKindNetwork, Target: addr, Status: status, Error: detail})
	}

	for _, addr := range targets {
		if blocked, ok := s.blockedTarget(addr); ok {
			if s.blockedHook != nil {
				s.blockedHook(ctx, blocked)
			}
			outcome(addr, TargetBlocked, blocked.Reason)
			continue
		}
		if ctx.Err() != nil {
			outcome(addr, TargetRejected, "scan canceled before the probe was submitted")
			continue
		}
		addr := addr
		wg.Add(1)
		task := func() {
			defer wg.Done()
			var (
				info certinfo.Info
				keys KeyObservation
				err  error
			)
			if s.chainProber != nil {
				info, keys, err = s.chainProber(ctx, addr)
			} else {
				info, err = s.prober(ctx, addr)
			}
			if err == nil {
				err = s.sink.Record(ctx, Found{Address: addr, Cert: info, Keys: keys})
			}
			if err != nil {
				outcome(addr, TargetFailed, err.Error())
			} else {
				outcome(addr, TargetSucceeded, "")
			}
		}
		if err := s.submit(ctx, task); err != nil {
			wg.Done()
			outcome(addr, TargetRejected, err.Error())
		}
	}

	wg.Wait()
	sort.Slice(rep.TargetResults, func(i, j int) bool { return rep.TargetResults[i].Target < rep.TargetResults[j].Target })
	return rep
}

func (s *Scanner) blockedTarget(addr string) (BlockedTarget, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return BlockedTarget{}, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return BlockedTarget{}, false
	}
	if s.allowLoopback && ip.IsLoopback() {
		return BlockedTarget{}, false
	}
	if netsec.BlockedIPWithOptions(ip, netsec.BlockedIPOptions{AllowRFC1918: s.allowRFC1918}) {
		return BlockedTarget{Address: addr, Reason: fmt.Sprintf("reserved IP %s blocked by SSRF guard", ip.String())}, true
	}
	return BlockedTarget{}, false
}

// submit enqueues task, throttling on backpressure: a retryable rejection (full
// queue) is retried after a backoff, so no target is dropped just because the
// pool is momentarily saturated. A permanent rejection (closed pool) or a
// canceled context returns an error.
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
