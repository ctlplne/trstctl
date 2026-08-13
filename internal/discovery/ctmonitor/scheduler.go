// SPDX-License-Identifier: MPL-2.0

package ctmonitor

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Persistence is the durable state a Scheduler reads and writes: the tenant's
// watched domains and per-log checkpoints. *store*-backed and in-memory
// implementations both satisfy it.
type Persistence interface {
	WatchedDomains(ctx context.Context, tenantID string) ([]string, error)
	Checkpoints(ctx context.Context, tenantID string) ([]LogState, error)
	SavePollResult(ctx context.Context, tenantID string, result LogPollResult) error
}

// RunResult keeps successful findings and one explicit outcome per configured
// log even when the aggregate pass is partial.
type RunResult struct {
	Findings []Finding
	Logs     []LogPollResult
}

func (r RunResult) FailedLogCount() int {
	count := 0
	for _, result := range r.Logs {
		if result.Status == LogPollFailed {
			count++
		}
	}
	return count
}

func (r RunResult) SucceededLogCount() int { return len(r.Logs) - r.FailedLogCount() }

const defaultInterval = 5 * time.Minute

// Scheduler drives the monitor from durable state: each pass loads the tenant's
// watched domains and CT-log checkpoints, polls every tracked log, raises alerts
// on unexpected issuance, and persists each advanced checkpoint so the next pass
// resumes where this one stopped.
type Scheduler struct {
	persist  Persistence
	fetch    Fetcher
	known    KnownGood
	alert    Alerter
	interval time.Duration
	maxBatch int
	monOpts  []Option
	onError  func(error)
}

// SchedulerOption configures a Scheduler.
type SchedulerOption func(*Scheduler)

// WithInterval sets how often Run polls (default 5m).
func WithInterval(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d > 0 {
			s.interval = d
		}
	}
}

// WithErrorHandler registers a callback for errors during Run, so a transient
// failure is observable without stopping the loop.
func WithErrorHandler(fn func(error)) SchedulerOption {
	return func(s *Scheduler) { s.onError = fn }
}

// WithMaxBatch bounds the number of entries read per log per pass.
func WithMaxBatch(n int) SchedulerOption {
	return func(s *Scheduler) {
		if n > 0 {
			s.maxBatch = n
		}
	}
}

// WithMonitorOptions forwards pool options to the Monitor each pass builds.
func WithMonitorOptions(opts ...Option) SchedulerOption {
	return func(s *Scheduler) { s.monOpts = append(s.monOpts, opts...) }
}

// NewScheduler builds a Scheduler over the persistence, fetcher, known-good
// check, and alerter.
func NewScheduler(p Persistence, fetch Fetcher, known KnownGood, alert Alerter, opts ...SchedulerOption) *Scheduler {
	s := &Scheduler{persist: p, fetch: fetch, known: known, alert: alert, interval: defaultInterval}
	for _, o := range opts {
		o(s)
	}
	return s
}

// RunOnce performs a single monitoring pass for the tenant. With no watched
// domains or no tracked logs it does nothing.
func (s *Scheduler) RunOnce(ctx context.Context, tenantID string) ([]Finding, error) {
	result, err := s.RunOnceDetailed(ctx, tenantID)
	return result.Findings, err
}

// RunOnceDetailed performs one monitoring pass without collapsing per-log
// truth. Successful checkpoints are persisted even when a peer log fails.
func (s *Scheduler) RunOnceDetailed(ctx context.Context, tenantID string) (RunResult, error) {
	domains, err := s.persist.WatchedDomains(ctx, tenantID)
	if err != nil {
		return RunResult{}, err
	}
	logs, err := s.persist.Checkpoints(ctx, tenantID)
	if err != nil {
		return RunResult{}, err
	}
	if len(domains) == 0 || len(logs) == 0 {
		return RunResult{}, nil
	}

	m := New(s.fetch, s.known, s.alert, Config{WatchedDomains: domains, MaxBatch: s.maxBatch}, s.monOpts...)
	outcomes, findings, pollErr := m.PollAllDetailed(ctx, tenantID, logs)

	var persistErrs []error
	for i := range outcomes {
		if err := s.persist.SavePollResult(ctx, tenantID, outcomes[i]); err != nil {
			persistErrs = append(persistErrs, fmt.Errorf("persist CT poll result for %s: %w", outcomes[i].URL, err))
			outcomes[i].Status = LogPollFailed
			outcomes[i].Error = boundedPollDetail(err.Error())
		}
	}
	return RunResult{Findings: findings, Logs: outcomes}, errors.Join(pollErr, errors.Join(persistErrs...))
}

// Run polls immediately and then every interval until ctx is cancelled, at which
// point it returns nil. An error from a pass is reported to the error handler
// (if registered) and does not stop the loop.
func (s *Scheduler) Run(ctx context.Context, tenantID string) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if _, err := s.RunOnce(ctx, tenantID); err != nil && s.onError != nil {
			s.onError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
