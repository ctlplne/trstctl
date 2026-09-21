// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/issuancerequest"
)

const (
	// issuanceExpiryInterval bounds how quickly an overdue request is noticed.
	// The request's own expires_at decides when it is due; this is detection
	// latency only.
	issuanceExpiryInterval = 5 * time.Minute
	// issuanceExpirySweepLimit caps one tenant's sweep so a tenant with a large
	// stale backlog cannot turn a single tick into an unbounded write (AN-7).
	issuanceExpirySweepLimit = 100
)

// RunIssuanceRequestExpiryOnce closes requests that ran out of time.
//
// Expiry is recorded with NO decider. Nobody chose it — time ran out — and
// stamping a person on it would put a decision in the audit trail that no human
// ever made. That is why expired and denied are separate states rather than one
// "closed" flag: a denial is somebody's judgment with a reason attached, an
// expiry is the absence of one, and a requester needs to tell those apart to
// know whether re-asking is reasonable.
func (s *Server) RunIssuanceRequestExpiryOnce(ctx context.Context) (int, error) {
	if s.store == nil || s.orch == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	tenants, err := s.store.TenantsWithExpirableIssuanceRequests(ctx, now)
	if err != nil {
		return 0, err
	}
	expired := 0
	var firstErr error
	for _, tenantID := range tenants {
		due, err := s.store.DueIssuanceRequests(ctx, tenantID, now, issuanceExpirySweepLimit)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, req := range due {
			if _, err := s.orch.DecideIssuanceRequest(ctx, tenantID, req.ID,
				issuancerequest.StateExpired, "", "No decision was made before the request expired.", ""); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				s.logger.Warn("issuance request expiry failed",
					slog.String("tenant_id", tenantID), slog.String("request_id", req.ID),
					slog.String("error", err.Error()))
				continue
			}
			expired++
		}
	}
	return expired, firstErr
}

// RunIssuanceRequestExpiry is the leader-only ticker.
func (s *Server) RunIssuanceRequestExpiry(ctx context.Context) {
	if s.store == nil || s.orch == nil {
		return
	}
	sweep := func() {
		n, err := s.RunIssuanceRequestExpiryOnce(ctx)
		if err != nil {
			s.logger.Warn("issuance request expiry sweep failed", slog.String("error", err.Error()))
		}
		if n > 0 {
			s.logger.Info("issuance requests expired", slog.Int("count", n))
		}
	}
	sweep()
	t := time.NewTicker(issuanceExpiryInterval)
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
