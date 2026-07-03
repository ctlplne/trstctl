package projections

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/events"
)

// LagSampler receives the current projection lag — the number of events the read
// model is behind the head of the log (SPINE-009). The control plane wires it to a
// metric gauge so operators can alert on a divergent/stuck projection.
type LagSampler func(lag float64)

// TailWorker is the tailing projection worker (SPINE-009): a durable consumer over
// the event stream that applies each new event to the read model and tracks how far
// behind the log head the projection is. It closes the gap the audit found — without
// it, an event from a non-orchestrator path was only projected on the next boot
// replay (silent lag), and there was no operator signal for divergence.
//
// The orchestrator still projects its own served writes inline (synchronously, in
// the same transaction as the outbox enqueue), so this worker is the at-least-once
// safety net and the lag signal, not the only writer; applying an already-projected
// event is an idempotent upsert.
type TailWorker struct {
	log       *events.Log
	proj      *Projector
	sampler   LagSampler
	applied   atomic.Uint64 // highest stream sequence known applied to the read model
	lagPeriod time.Duration
}

// NewTailWorker returns a tailing projection worker over log and proj. sampler may
// be nil (no lag metric). lagPeriod is how often lag is sampled (a non-positive
// value uses a sensible default).
func NewTailWorker(log *events.Log, proj *Projector, sampler LagSampler, lagPeriod time.Duration) *TailWorker {
	if lagPeriod <= 0 {
		lagPeriod = 5 * time.Second
	}
	return &TailWorker{log: log, proj: proj, sampler: sampler, lagPeriod: lagPeriod}
}

// Applied returns the highest stream sequence known applied to the read model. It
// backs the lag computation and is initialized from the persisted projection
// checkpoint, so a clean restart does not report historical events as lag.
func (w *TailWorker) Applied() uint64 { return w.applied.Load() }

// Lag returns the current projection lag: the stream head sequence minus the highest
// sequence this worker has applied (0 when caught up). It is exported so a test can
// assert the lag returns to zero after the worker drains, and the server can sample
// it into a metric (SPINE-009).
func (w *TailWorker) Lag(ctx context.Context) (uint64, error) {
	if err := w.syncAppliedCheckpoint(ctx); err != nil {
		return 0, err
	}
	last, err := w.log.LastSequence(ctx)
	if err != nil {
		return 0, err
	}
	applied := w.applied.Load()
	if last <= applied {
		return 0, nil
	}
	return last - applied, nil
}

// Run tails the event stream and applies every event to the read model through the
// durable consumer until ctx is cancelled (SPINE-009). It also samples projection
// lag on a fixed cadence into the configured sampler. It is meant to run in its own
// goroutine; a tail error (e.g. a poison event leaving the cursor stuck) is returned
// so the caller can log it and the lag metric surfaces the stall.
func (w *TailWorker) Run(ctx context.Context) error {
	if err := w.syncAppliedCheckpoint(ctx); err != nil {
		return err
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if w.sampler != nil {
		go w.sampleLagLoop(runCtx)
	}
	return w.log.Tail(runCtx, func(e events.Event) error {
		if err := w.proj.Apply(runCtx, e); err != nil {
			return err
		}
		// Advance the projection checkpoint as the tail applies out-of-band events
		// (SPINE-007), so the boot catch-up watermark stays current and a restart
		// resumes from the tail's position rather than re-replaying. A failure to
		// advance is non-fatal: the watermark is an optimization, not a correctness
		// boundary (Apply is an idempotent upsert), so we keep tailing.
		if err := w.proj.AdvanceCheckpoint(runCtx, e.Sequence); err != nil {
			return err
		}
		w.applied.Store(e.Sequence)
		return nil
	})
}

// syncAppliedCheckpoint folds the durable projection checkpoint into the
// process-local watermark. The read model lives in PostgreSQL and survives a clean
// restart; without this max(), a fresh worker starts at zero and its lag metric
// counts already-projected historical events as if they were still pending.
func (w *TailWorker) syncAppliedCheckpoint(ctx context.Context) error {
	checkpoint, err := w.proj.store.ProjectionCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("projections: read tail checkpoint: %w", err)
	}
	for {
		applied := w.applied.Load()
		if checkpoint <= applied {
			return nil
		}
		if w.applied.CompareAndSwap(applied, checkpoint) {
			return nil
		}
	}
}

// sampleLagLoop periodically samples projection lag into the sampler until ctx is
// cancelled, so the lag gauge reflects a stuck or catching-up projection even when no
// new events are arriving.
func (w *TailWorker) sampleLagLoop(ctx context.Context) {
	t := time.NewTicker(w.lagPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if lag, err := w.Lag(ctx); err == nil {
				w.sampler(float64(lag))
			}
		}
	}
}
