// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Only the elected worker owns this cursor. Advance before trying a job: a
// timeout or missing receipt must not send the next tick back to the same job.
// Per-job source positions are persisted separately and survive process restarts.
type hostRotationRecoveryCursor struct {
	Tenant   string
	AfterJob int64
}

func (s *Server) reconcileHostRotationResults(ctx context.Context, cursor *hostRotationRecoveryCursor) error {
	if s.store == nil || s.orch == nil || s.log == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	receiver := &agentService{store: s.store, log: s.log, orch: s.orch}
	var failures []error
	// Bound both empty-registry work and job work, in addition to the deadline.
	for steps := 0; steps < 16 && ctx.Err() == nil; steps++ {
		if cursor.Tenant == "" {
			next, err := s.store.NextHostRotationRecoveryTenant(ctx, "")
			if err != nil {
				return errors.Join(append(failures, err)...)
			}
			if next == "" {
				break
			}
			cursor.Tenant = next
		}
		ids, err := s.store.PendingHostRotationResults(ctx, cursor.Tenant, cursor.AfterJob)
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		if len(ids) == 0 {
			next, err := s.store.NextHostRotationRecoveryTenant(ctx, cursor.Tenant)
			if err != nil {
				return errors.Join(append(failures, err)...)
			}
			*cursor = hostRotationRecoveryCursor{Tenant: next}
			if next == "" {
				break
			} // One registry traversal per tick; retry on the next tick.
			continue
		}
		id := ids[0]
		cursor.AfterJob = id
		if err := receiver.recordHostRotationResult(ctx, cursor.Tenant, id); err != nil && !errors.Is(err, errHostRotationLookupPending) {
			failures = append(failures, fmt.Errorf("host rotation recovery tenant %s job %d: %w", cursor.Tenant, id, err))
		}
	}
	return errors.Join(failures...)
}

// RunHostRotationRecovery is a separate bounded, leader-owned worker. It never
// makes a CSR, deploys, or reclaims a host job; it projects retained observations.
func (s *Server) RunHostRotationRecovery(ctx context.Context) {
	var cursor hostRotationRecoveryCursor
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.reconcileHostRotationResults(ctx, &cursor); err != nil && ctx.Err() == nil && s.logger != nil {
			s.logger.Warn("host rotation result recovery incomplete", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
