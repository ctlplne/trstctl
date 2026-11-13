// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/config"
	corestore "trstctl.com/trstctl/internal/store"
)

// The Provider's documentation record sweep (MSP-14): on the leader, for
// every documentation target and every customer mapped to an organization
// there, one sync per interval is queued; the core outbox renders the
// customer's certificate inventory and writes it to the customer's record
// only when it changed. The sweep never calls the documentation system.

// DocQueuer is the core command side the sweep drives.
type DocQueuer interface {
	QueueDocRecord(ctx context.Context, tenantID, targetID string, bucket time.Time) (bool, error)
}

type docQueuerBox struct{ q DocQueuer }

// DocTargets are the configured documentation targets.
func DocTargets(sync config.ProviderBillingSync) []config.ProviderBillingTarget {
	var out []config.ProviderBillingTarget
	for _, t := range sync.Targets {
		if t.IsDocumentation() {
			out = append(out, t)
		}
	}
	return out
}

// docMaxSyncsPerSweep bounds one sweep (backpressure).
const docMaxSyncsPerSweep = 2000

// DocSweeper is the leader worker.
type DocSweeper struct {
	Store    *corestore.Store
	Targets  []config.ProviderBillingTarget
	Interval time.Duration
	Log      *slog.Logger
	Now      func() time.Time

	queuer atomic.Pointer[docQueuerBox]
}

// Bind attaches the core command side; until then a sweep does nothing.
func (s *DocSweeper) Bind(q DocQueuer) {
	if s != nil && q != nil {
		s.queuer.Store(&docQueuerBox{q: q})
	}
}

// Name identifies the worker.
func (s *DocSweeper) Name() string { return "provider.doc_record.sweep" }

func (s *DocSweeper) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return 10 * time.Minute
}

// Run sweeps every interval until ctx ends.
func (s *DocSweeper) Run(ctx context.Context) error {
	for {
		if _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil && s.Log != nil {
			s.Log.Warn("documentation record sweep failed", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.interval()):
		}
	}
}

// Sweep queues this interval's sync for every mapped customer of every
// documentation target and reports how many it queued.
func (s *DocSweeper) Sweep(ctx context.Context) (int, error) {
	box := s.queuer.Load()
	if box == nil || s.Store == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	bucket := now.Truncate(s.interval())
	queued, work := 0, 0
	var firstErr error
	for _, target := range s.Targets {
		if !target.IsDocumentation() {
			continue
		}
		mappings, err := s.Store.BillingCompanyMappings(ctx, target.ID)
		if err != nil {
			return queued, err
		}
		for _, m := range mappings {
			if work >= docMaxSyncsPerSweep || ctx.Err() != nil {
				return queued, firstErr
			}
			work++
			ok, err := box.q.QueueDocRecord(ctx, m.TenantID, target.ID, bucket)
			if err != nil {
				firstErr = errors.Join(firstErr, err)
				continue
			}
			if ok {
				queued++
			}
		}
	}
	return queued, firstErr
}
