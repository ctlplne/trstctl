// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rounds

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/server"
)

type WorkerOptions struct {
	Log       EventAppender
	Source    DigestSource
	Schedules []Config
	Interval  time.Duration
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
	schedulers := make([]*Scheduler, 0, len(w.opts.Schedules))
	for _, cfg := range w.opts.Schedules {
		s, err := NewScheduler(cfg, w.opts.Source, w.opts.Log)
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
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
