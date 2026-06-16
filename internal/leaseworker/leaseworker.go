// Package leaseworker is the supervised, durable lease-expiry worker (S19.0): it
// periodically sweeps expired dynamic-secret leases and drains the revocation
// outbox, so a backend credential is revoked at expiry even across control-plane
// restarts (AN-6). On startup it Recover()s — draining any revocations the durable
// queue still holds from a prior (possibly crashed) run — and on shutdown it stops
// cleanly without stranding or double-revoking leases.
package leaseworker

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
)

// Engine is the lease engine the worker drives. *dynsecret.Engine satisfies it.
type Engine interface {
	ExpireDue(ctx context.Context, now time.Time) (int, error)
	RunRevocations(ctx context.Context) (int, error)
}

// Compile-time proof the dynamic-secrets engine is a valid worker engine.
var _ Engine = (*dynsecret.Engine)(nil)

// Worker sweeps and drains on an interval.
type Worker struct {
	engine   Engine
	interval time.Duration
	clock    func() time.Time
}

// New constructs a Worker.
func New(engine Engine, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Worker{engine: engine, interval: interval, clock: time.Now}
}

// Recover drains revocations left in the durable queue by a prior run (the
// restart-recovery path). Call once on startup before serving.
func (w *Worker) Recover(ctx context.Context) (int, error) {
	return w.engine.RunRevocations(ctx)
}

// Tick performs one sweep: expire due leases (enqueuing their revocations) then
// drain the revocation queue.
func (w *Worker) Tick(ctx context.Context) (expired, revoked int, err error) {
	expired, err = w.engine.ExpireDue(ctx, w.clock())
	if err != nil {
		return expired, 0, err
	}
	revoked, err = w.engine.RunRevocations(ctx)
	return expired, revoked, err
}

// Run loops, ticking every interval, until ctx is cancelled (graceful stop). It
// performs a final drain on shutdown so an in-flight expiry is not stranded.
func (w *Worker) Run(ctx context.Context) error {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = w.engine.RunRevocations(drainCtx)
			return ctx.Err()
		case <-t.C:
			if _, _, err := w.Tick(ctx); err != nil {
				// fail-safe: keep running; the durable queue retains unrevoked items
				continue
			}
		}
	}
}
