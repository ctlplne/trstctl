// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Access review reconcile (Q1). On the leader, every revoke decision that has
// not closed is visited each minute: an act its decision request never
// recorded runs now with the item's idempotency key, and an item closes only
// when its credential reads revoked or is gone. A certified item whose next
// review date has passed gets its next review (Q1-L7).

const nhiReviewReconcileInterval = time.Minute

// nhiReviewReconcileActor names the reconcile in the events it appends; the
// revoke itself still records the reviewer as its requester. A next review it
// opens (Q1-L7) names it as the campaign's requester.
const nhiReviewReconcileActor = store.NHIReviewSchedulerSubject

// RunNHIReviewReconcile finishes access review revoke decisions on the leader.
func (s *Server) RunNHIReviewReconcile(ctx context.Context) {
	ticker := time.NewTicker(nhiReviewReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.ReconcileNHIReviewsOnce(ctx); err != nil && s.logger != nil {
				s.logger.Warn("access review reconcile could not finish every revoke decision", slog.String("error", err.Error()))
			}
		}
	}
}

// ReconcileNHIReviewsOnce visits every tenant holding a revoke decision that
// has not closed, under that tenant's own context, and opens the next review
// of every certified item whose next review date has passed (Q1-L7).
func (s *Server) ReconcileNHIReviewsOnce(ctx context.Context) error {
	if s.store == nil || s.api == nil {
		return nil
	}
	tenants, err := s.store.TenantsWithNHIReviewItemsAwaitingClosure(ctx)
	if err != nil {
		return err
	}
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: nhiReviewReconcileActor})
	var firstErr error
	for _, tenantID := range tenants {
		if _, err := s.api.ReconcileNHIReviewRevocations(actorCtx, tenantID, time.Now().UTC()); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("tenant %s: %w", tenantID, err)
		}
	}
	if s.orch == nil {
		return firstErr
	}
	now := time.Now().UTC()
	due, err := s.store.TenantsWithNHIReviewsDue(ctx, now)
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
		return firstErr
	}
	for _, tenantID := range due {
		if _, err := s.orch.OpenDueNHINextReviews(actorCtx, tenantID, now); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("tenant %s next review: %w", tenantID, err)
		}
	}
	return firstErr
}
