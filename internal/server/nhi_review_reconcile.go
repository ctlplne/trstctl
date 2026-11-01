// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/events"
)

// Access review reconcile (Q1). On the leader, every revoke decision that has
// not closed is visited each minute: an act its decision request never
// recorded runs now with the item's idempotency key, and an item closes only
// when its credential reads revoked.

const nhiReviewReconcileInterval = time.Minute

// nhiReviewReconcileActor names the reconcile in the events it appends; the
// revoke itself still records the reviewer as its requester.
const nhiReviewReconcileActor = "trstctl:access-review-reconcile"

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
// has not closed, under that tenant's own context.
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
	return firstErr
}
