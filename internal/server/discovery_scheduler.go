// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

const (
	// discoverySchedulerInterval is how often the leader sweeps for due
	// discovery schedules. Each schedule's own interval_seconds decides when
	// it is due; this cadence only bounds detection latency.
	discoverySchedulerInterval = time.Minute
	// discoverySchedulerSweepLimit caps how many runs one tenant sweep may
	// queue, so a tenant with thousands of overdue schedules cannot flood the
	// discovery worker in one tick — the remainder is picked up next sweep
	// (AN-7 discipline ahead of the bulkheaded worker).
	discoverySchedulerSweepLimit = 100
	// discoverySchedulerActor is the RequestedBy recorded on scheduler-queued
	// runs, so operators can tell ticker runs from operator-initiated ones.
	discoverySchedulerActor = "discovery-scheduler"
)

// RunDiscoverySchedulerOnce sweeps every tenant's due discovery schedules and
// queues one run per due schedule through the normal orchestrator path — the
// same event + projection + outbox pipeline an operator-initiated run takes
// (AN-2/AN-5/AN-6), so a scheduler run is indistinguishable downstream except
// for its RequestedBy. A schedule is due when its source has no in-flight run
// and no run newer than its interval (the due decision lives in
// store.DiscoverySchedulesDue). Returns how many runs were queued; per-tenant
// errors are logged and do not stop the sweep of other tenants.
func (s *Server) RunDiscoverySchedulerOnce(ctx context.Context) (int, error) {
	if s.orch == nil || s.store == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithEnabledDiscoverySchedules(ctx)
	if err != nil {
		return 0, err
	}
	queued := 0
	var firstErr error
	for _, tenantID := range tenants {
		due, err := s.store.DiscoverySchedulesDue(ctx, tenantID, time.Now(), discoverySchedulerSweepLimit)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.logger.Warn("discovery scheduler: list due schedules failed",
				slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
			continue
		}
		for _, sched := range due {
			scheduleID := sched.ID
			if _, err := s.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
				SourceID:    sched.SourceID,
				ScheduleID:  &scheduleID,
				RequestedBy: discoverySchedulerActor,
				OnlyIfDue:   true,
			}); err != nil {
				if errors.Is(err, orchestrator.ErrDiscoveryScheduleNotDue) {
					continue
				}
				if firstErr == nil {
					firstErr = err
				}
				s.logger.Warn("discovery scheduler: queue run failed",
					slog.String("tenant_id", tenantID),
					slog.String("schedule_id", sched.ID),
					slog.String("source_id", sched.SourceID),
					slog.String("error", err.Error()))
				continue
			}
			queued++
		}
	}
	return queued, firstErr
}

// RunDiscoveryScheduler runs the leader-only discovery schedule ticker until
// ctx is cancelled: it sweeps once on start (so an overdue deployment catches
// up promptly after boot) and then on a fixed cadence. A sweep error is logged
// and the next tick retries — the same resilient pattern the CRL and lifecycle
// schedulers use. It is a no-op when the spine is not assembled.
func (s *Server) RunDiscoveryScheduler(ctx context.Context) {
	if s.orch == nil || s.store == nil {
		return
	}
	sweep := func() {
		n, err := s.RunDiscoverySchedulerOnce(ctx)
		if err != nil {
			s.logger.Warn("discovery scheduler sweep failed", slog.String("error", err.Error()))
		}
		if n > 0 {
			s.logger.Info("discovery scheduler queued runs", slog.Int("queued", n))
		}
	}
	sweep()
	t := time.NewTicker(discoverySchedulerInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
