// Package leader provides single-leader election for the control plane's continuous
// background workers (RESIL-004 / EXC-RESIL-01). When trstctl runs multiple
// control-plane replicas (the HA topology RESIL-002 unlocks), every replica serves
// reads, but only ONE — the leader — runs the workers that mutate shared state on a
// continuous cadence: the projector tailer, the outbox dispatcher, the
// idempotency/outbox GC sweeps, the CRL freshness scheduler, the audit-retention
// worker, and the read-model snapshot worker. This prevents N replicas from
// double-applying (the projector tailer in particular has no other coordination once
// it is past the boot catch-up's advisory lock).
//
// Leadership is a PostgreSQL session-scoped advisory lock (store.TryBecomeLeader): it
// is held for as long as the leader's connection lives and is released AUTOMATICALLY
// by PostgreSQL if that connection drops, so a crashed or partitioned leader frees the
// lock and a follower takes over on its next campaign — failover with no lease timer
// and no extra datastore (CLAUDE.md §5: no Redis). It is fail-safe: a replica that
// cannot win the lock simply stays a follower and serves reads; nothing about
// issuance or query serving depends on being the leader.
package leader

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// DefaultCampaignInterval is how often a follower re-attempts to acquire leadership,
// and how often the leader re-checks it still holds the lock. A few seconds gives
// prompt failover (a new leader is elected within ~one interval of the old one
// dropping) without hammering the database with try-lock probes.
const DefaultCampaignInterval = 3 * time.Second

// Elector campaigns for leadership against the shared store and, while it holds it,
// runs a caller-supplied leader function. Exactly one Elector across all replicas
// runs its leader function at a time.
type Elector struct {
	store    *store.Store
	logger   *slog.Logger
	interval time.Duration
	// onLeader runs the leader-only work. It is given a context that is cancelled the
	// moment leadership is lost (the lock dropped) or the Elector is stopped, so the
	// continuous workers it starts stop promptly and another replica can take over
	// without two leaders overlapping. onLeader is expected to block until that context
	// is cancelled; if it returns early, the Elector steps down and re-campaigns.
	onLeader func(ctx context.Context)
}

// Option configures an Elector.
type Option func(*Elector)

// WithInterval sets the campaign/health-check cadence (a non-positive value keeps the
// default).
func WithInterval(d time.Duration) Option {
	return func(e *Elector) {
		if d > 0 {
			e.interval = d
		}
	}
}

// WithLogger sets the structured logger for leadership transitions (nil discards).
func WithLogger(l *slog.Logger) Option {
	return func(e *Elector) { e.logger = l }
}

// New returns an Elector that campaigns against s and runs onLeader while it is the
// leader. onLeader must block until its context is cancelled (it receives a context
// that is cancelled on leadership loss or shutdown).
func New(s *store.Store, onLeader func(ctx context.Context), opts ...Option) *Elector {
	e := &Elector{store: s, interval: DefaultCampaignInterval, onLeader: onLeader}
	for _, o := range opts {
		o(e)
	}
	if e.logger == nil {
		e.logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	return e
}

// Run campaigns for leadership until ctx is cancelled (RESIL-004). It loops: try to
// become leader; if it loses the race it waits one interval and retries (staying a
// follower); if it wins, it runs onLeader with a leadership-scoped context and
// monitors the lock, cancelling that context and stepping down the instant the lock
// is lost — then re-campaigns. It is meant to run in its own goroutine and returns
// when ctx is cancelled (after a graceful step-down).
func (e *Elector) Run(ctx context.Context) {
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		lease, err := e.store.TryBecomeLeader(ctx)
		switch {
		case errors.Is(err, store.ErrNotLeader):
			// Another replica leads. Stay a follower and retry next tick.
		case err != nil:
			// Transient error acquiring the lock (e.g. the DB is briefly unreachable). Log
			// and retry; we do NOT assume leadership on error (fail safe).
			if ctx.Err() == nil {
				e.logger.Warn("leader election: acquire attempt failed; staying follower", slog.String("error", err.Error()))
			}
		default:
			// We are the leader. Serve the leader work until we lose the lock or shut down.
			e.serveAsLeader(ctx, lease)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// serveAsLeader runs onLeader under a context cancelled on leadership loss, and
// monitors the lease. It returns (and the lease is released) when the lock is lost,
// onLeader returns, or ctx is cancelled — so the next campaign can re-elect.
func (e *Elector) serveAsLeader(ctx context.Context, lease *store.LeaderLease) {
	defer lease.Release()
	e.logger.Info("leader election: this replica is now the leader (running continuous background workers)")

	leaderCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.onLeader(leaderCtx)
	}()

	// Monitor the lock: if the connection (and thus the lock) dies, cancel the leader
	// context so the workers stop, then step down. The check cadence matches the
	// campaign interval so failover is prompt.
	hc := time.NewTicker(e.interval)
	defer hc.Stop()
	for {
		select {
		case <-ctx.Done():
			cancel()
			<-done
			e.logger.Info("leader election: stepping down (shutdown)")
			return
		case <-done:
			// onLeader returned on its own (unexpected unless it errored out). Step down so
			// another replica — or this one on the next campaign — can take leadership.
			e.logger.Warn("leader election: leader workers exited; stepping down")
			return
		case <-hc.C:
			if !lease.Healthy(ctx) {
				e.logger.Warn("leader election: lost the leader lock; stepping down for failover")
				cancel()
				<-done
				return
			}
		}
	}
}

// discard is an io.Writer that drops everything, used to build a no-op default logger
// when the caller supplies none.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
