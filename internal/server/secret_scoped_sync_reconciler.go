// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/api"
)

// Continuous scoped sync (A237). On the leader, each tick visits the tenants
// holding an auto scoped sync; a definition whose source set changed (or whose
// drift check is due) is re-planned, and a plan with changes and nothing
// blocked is applied like a reviewed apply. A blocked plan is recorded on the
// definition and waits for a person.

const (
	defaultScopedSyncReconcileInterval = 30 * time.Second
	scopedSyncDriftInterval            = 15 * time.Minute
)

// RunScopedSyncReconciler reconciles auto scoped syncs until ctx ends.
func (s *Server) RunScopedSyncReconciler(ctx context.Context) {
	interval := s.scopedSyncReconcileInterval
	if interval <= 0 {
		interval = defaultScopedSyncReconcileInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.ReconcileScopedSyncsOnce(ctx); err != nil && s.logger != nil {
				s.logger.Warn("scoped sync reconcile could not finish every definition", slog.String("error", err.Error()))
			}
		}
	}
}

// ReconcileScopedSyncsOnce runs one reconcile pass and returns how many plans
// it applied. The pass remembers each definition's source set between calls.
func (s *Server) ReconcileScopedSyncsOnce(ctx context.Context) (int, error) {
	if s.api == nil || s.store == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithAutoScopedSyncs(ctx)
	if err != nil || len(tenants) == 0 {
		return 0, err
	}
	s.scopedSyncReconcileMu.Lock()
	defer s.scopedSyncReconcileMu.Unlock()
	if s.scopedSyncReconcileState == nil {
		s.scopedSyncReconcileState = api.ScopedSyncReconcileState{}
	}
	return s.api.ReconcileScopedSecretSyncs(ctx, tenants, s.scopedSyncReconcileState, time.Now().UTC(), scopedSyncDriftInterval)
}
