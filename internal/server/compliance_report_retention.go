// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/reportarchive"
	"trstctl.com/trstctl/internal/store"
)

// A206: the opt-in report retention (audit.report_retention). Each scheduler
// sweep finds completed runs older than the window that no person holds and
// records an expiry request for each; its projection marks the run and queues
// the removal in the same transaction, so the next sweep skips it. The outbox
// delivery removes the report where the run's reference says, confirms it is
// gone, and records the expiry. A hold, a request and a removal of one run all
// take the run's lock, so a report is never removed after a person held it,
// and a hold cancels a queued removal.

const complianceReportRetentionSweepLimit = 100

// complianceReportLegalHoldRecheck is how long a removal waits behind an S3
// legal hold, which has no end date of its own, before the retention asks
// again.
const complianceReportLegalHoldRecheck = 24 * time.Hour

// expireComplianceReportsOnce queues the removal of up to 100 reports past the
// retention window.
func (s *Server) expireComplianceReportsOnce(ctx context.Context, now time.Time) (int, error) {
	if s.reportRetention <= 0 || s.store == nil || s.orch == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithCompletedComplianceReports(ctx)
	if err != nil {
		return 0, err
	}
	cutoff := now.Add(-s.reportRetention)
	requested := 0
	for _, tenantID := range tenants {
		if requested >= complianceReportRetentionSweepLimit {
			break
		}
		due, err := s.store.ComplianceReportRunsPastRetention(ctx, tenantID, cutoff, now, complianceReportRetentionSweepLimit-requested)
		if err != nil {
			return requested, err
		}
		for _, candidate := range due {
			queued := false
			// A busy run (a hold change, its own removal, an overlapping
			// leader) is left for the next sweep.
			if _, err := s.store.WithComplianceReportRunLock(ctx, candidate.TenantID, candidate.ScheduleID, candidate.DueAt, func() error {
				run, err := s.store.GetComplianceReportRun(ctx, candidate.TenantID, candidate.ID)
				if err != nil {
					return err
				}
				if run.Status != "completed" || run.Retention.Held() || run.Retention.ExpiryRequestedAt != nil ||
					run.Retention.ArtifactExpiredAt != nil || !run.CompletedAt.Before(cutoff) ||
					(run.Retention.StorageLockedUntil != nil && now.Before(*run.Retention.StorageLockedUntil)) {
					return nil
				}
				if err := s.orch.RequestComplianceReportArtifactExpiry(ctx, run, s.reportRetention); err != nil {
					return err
				}
				queued = true
				return nil
			}); err != nil {
				return requested, err
			}
			if queued {
				requested++
			}
		}
	}
	return requested, nil
}

// complianceReportExpiry is the outbox delivery that removes one report.
type complianceReportExpiry struct {
	store   *store.Store
	orch    *orchestrator.Orchestrator
	archive reportarchive.Archive
	now     func() time.Time
}

func (e *complianceReportExpiry) Deliver(ctx context.Context, m orchestrator.Message) error {
	if e == nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: report retention is not configured"))
	}
	var pl projections.ComplianceReportArtifactExpiry
	if err := json.Unmarshal(m.Payload, &pl); err != nil || pl.RunID == "" {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: report expiry payload: %v", err))
	}
	run, err := e.store.GetComplianceReportRun(ctx, m.TenantID, pl.RunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return orchestrator.DefiniteNoEffect(errors.New("server: the report run is gone"))
	}
	if err != nil {
		return err
	}
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	var outcome error
	acquired, err := e.store.WithComplianceReportRunLock(ctx, run.TenantID, run.ScheduleID, run.DueAt, func() error {
		current, err := e.store.GetComplianceReportRun(ctx, run.TenantID, run.ID)
		if err != nil {
			return err
		}
		// Already removed, held since the request, or not this report: the
		// delivery completes without touching anything.
		if current.Retention.ArtifactExpiredAt != nil || current.Retention.Held() || current.ArtifactDigest != pl.Digest {
			return nil
		}
		if err := e.archive.Remove(ctx, current.ArtifactRef, current.TenantID, current.ID, current.ArtifactDigest); err != nil {
			// A208: the archive's Object Lock protects the report. Record
			// until when, so the sweep asks again then instead of retrying.
			var locked *objectstore.ErrLocked
			if errors.As(err, &locked) {
				until := locked.Until
				if locked.LegalHold || until.IsZero() {
					until = now().Add(complianceReportLegalHoldRecheck)
				}
				return e.orch.DeferComplianceReportArtifactExpiry(ctx, current.TenantID, current.ID, current.ArtifactDigest, until, locked.LegalHold)
			}
			outcome = fmt.Errorf("server: remove report %s under retention: %w", current.ID, err)
			return nil
		}
		gone, err := e.archive.Gone(ctx, current.ArtifactRef, current.TenantID, current.ID, current.ArtifactDigest)
		if err != nil || !gone {
			outcome = fmt.Errorf("server: report %s is still present after removal (%v)", current.ID, err)
			return nil
		}
		return e.orch.RecordComplianceReportArtifactExpired(ctx, current.TenantID, current.ID, current.ArtifactDigest,
			time.Duration(pl.RetentionSeconds)*time.Second, now())
	})
	if err != nil {
		return err
	}
	if !acquired {
		// A hold change holds the run's lock; the outbox retries.
		return fmt.Errorf("server: report %s is busy; the removal retries", run.ID)
	}
	return outcome
}
