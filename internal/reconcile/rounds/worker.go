// SPDX-License-Identifier: BUSL-1.1

package rounds

import (
	"context"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/server"
)

type WorkerOptions struct {
	Log       EventAppender
	Source    DigestSource
	Schedules []Config
	Interval  time.Duration
	// Sink turns detected digest disagreements into recorded witnesses. Nil
	// reproduces the pre-C4 silence, so the runtime always supplies one.
	Sink DisagreementSink
	// Logger reports round errors. Rounds run for the life of the process; an
	// error in one round is a log line and a retry next tick, not a dead worker.
	Logger *slog.Logger
}

func NewWorkers(opts WorkerOptions) []server.BackgroundWorker {
	return []server.BackgroundWorker{&worker{opts: opts}}
}

type worker struct {
	opts WorkerOptions
}

func (w *worker) Name() string { return "xrec.rounds" }

func (w *worker) Run(ctx context.Context) error {
	if w.opts.Log == nil || w.opts.Source == nil || len(w.opts.Schedules) == 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	interval := w.opts.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	var opts []Option
	if w.opts.Sink != nil {
		opts = append(opts, WithDisagreementSink(w.opts.Sink))
	}
	schedulers := make([]*Scheduler, 0, len(w.opts.Schedules))
	for _, cfg := range w.opts.Schedules {
		s, err := NewScheduler(cfg, w.opts.Source, w.opts.Log, opts...)
		if err != nil {
			return err
		}
		schedulers = append(schedulers, s)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, scheduler := range schedulers {
			if _, _, err := scheduler.RunDue(ctx); err != nil {
				// Before C4 this error KILLED the worker: one transient store or
				// signer failure ended reconciliation for the life of the
				// process, silently, while the worker stayed registered and
				// healthy-looking in the roster. The round already recorded
				// whatever divergence evidence it could; the schedule's next
				// due time has advanced; the correct response is to say so and
				// keep comparing.
				if w.opts.Logger != nil {
					w.opts.Logger.Warn("xrec round failed",
						slog.String("tenant_id", scheduler.cfg.TenantID),
						slog.String("error", err.Error()))
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
