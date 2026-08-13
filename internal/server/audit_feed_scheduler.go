// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/audit"
)

const (
	auditFeedSchedulerInterval = time.Minute
	auditFeedSchedulerLimit    = 100
)

// RunAuditFeedSchedulerOnce turns due tenant destinations into exact immutable
// batches. It performs no network I/O; the normal bounded outbox family owns
// delivery and retry.
func (s *Server) RunAuditFeedSchedulerOnce(ctx context.Context) (int, error) {
	if s == nil || s.store == nil || s.orch == nil || s.audit == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithEnabledAuditFeeds(ctx)
	if err != nil {
		return 0, err
	}
	queued := 0
	var firstErr error
	now := time.Now().UTC()
	for _, tenantID := range tenants {
		feeds, err := s.store.AuditFeedsDue(ctx, tenantID, now, auditFeedSchedulerLimit)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, feed := range feeds {
			records, seed, err := s.audit.SearchWithSeed(ctx, audit.Query{
				TenantID: tenantID, AfterSequence: feed.LastDeliveredSequence,
				ExcludeTypePrefixes: []string{"audit.feed."}, Limit: feed.BatchSize,
			})
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if len(records) == 0 {
				if err := s.orch.RecordAuditFeedScheduleChecked(ctx, tenantID, feed); err != nil && firstErr == nil {
					firstErr = err
				}
				continue
			}
			chainHead := records[len(records)-1].Hash
			if _, err := s.orch.QueueAuditFeedBatch(ctx, tenantID, feed, records, seed, chainHead); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			queued++
		}
	}
	if queued > 0 {
		s.wakeOutbox()
	}
	return queued, firstErr
}

func (s *Server) RunAuditFeedScheduler(ctx context.Context) {
	if s == nil || s.store == nil || s.orch == nil || s.audit == nil {
		return
	}
	run := func() {
		if n, err := s.RunAuditFeedSchedulerOnce(ctx); err != nil {
			s.logger.Warn("audit feed scheduler sweep failed", slog.String("error", err.Error()))
		} else if n > 0 {
			s.logger.Info("audit feed scheduler queued batches", slog.Int("queued", n))
		}
	}
	run()
	ticker := time.NewTicker(auditFeedSchedulerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
