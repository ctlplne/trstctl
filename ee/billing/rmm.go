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

// The Provider's RMM inventory sweep (MSP-9): on the leader, for every RMM
// target and every customer mapped to an organization there, one inventory
// per interval is queued; the core outbox lists the devices, maps them to
// the customer's agents and reports health back. The sweep never calls the
// RMM itself.

// RMMQueuer is the core command side the sweep drives.
type RMMQueuer interface {
	QueueRMMInventory(ctx context.Context, tenantID, targetID string, bucket time.Time) (bool, error)
}

type rmmQueuerBox struct{ q RMMQueuer }

// RMMTargets are the configured targets that run agents through an RMM.
func RMMTargets(sync config.ProviderBillingSync) []config.ProviderBillingTarget {
	var out []config.ProviderBillingTarget
	for _, t := range sync.Targets {
		if t.IsRMM() {
			out = append(out, t)
		}
	}
	return out
}

// rmmMaxInventoriesPerSweep bounds one sweep (backpressure).
const rmmMaxInventoriesPerSweep = 2000

// RMMSweeper is the leader worker.
type RMMSweeper struct {
	Store    *corestore.Store
	Targets  []config.ProviderBillingTarget
	Interval time.Duration
	Log      *slog.Logger
	Now      func() time.Time

	queuer atomic.Pointer[rmmQueuerBox]
}

// Bind attaches the core command side; until then a sweep does nothing.
func (s *RMMSweeper) Bind(q RMMQueuer) {
	if s != nil && q != nil {
		s.queuer.Store(&rmmQueuerBox{q: q})
	}
}

// Name identifies the worker.
func (s *RMMSweeper) Name() string { return "provider.rmm.inventory_sweep" }

func (s *RMMSweeper) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return 10 * time.Minute
}

// Run sweeps every interval until ctx ends.
func (s *RMMSweeper) Run(ctx context.Context) error {
	for {
		if _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil && s.Log != nil {
			s.Log.Warn("RMM inventory sweep failed", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.interval()):
		}
	}
}

// Sweep queues this interval's inventory for every mapped customer of every
// RMM target and reports how many it queued.
func (s *RMMSweeper) Sweep(ctx context.Context) (int, error) {
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
		if !target.IsRMM() {
			continue
		}
		mappings, err := s.Store.BillingCompanyMappings(ctx, target.ID)
		if err != nil {
			return queued, err
		}
		for _, m := range mappings {
			if work >= rmmMaxInventoriesPerSweep || ctx.Err() != nil {
				return queued, firstErr
			}
			work++
			ok, err := box.q.QueueRMMInventory(ctx, m.TenantID, target.ID, bucket)
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
