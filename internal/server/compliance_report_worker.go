// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/reportarchive"
	"trstctl.com/trstctl/internal/store"
)

const (
	complianceReportSweepInterval = time.Minute
	complianceReportSweepLimit    = 100
	complianceReportTenantBatch   = 5
)

// RunComplianceReportScheduler owns only scheduled-report work. A slow report
// cannot occupy the outbox, lifecycle or API pools. The due query and one
// session lock per due edge bound each sweep and prevent duplicate signatures
// across leader failover.
func (s *Server) RunComplianceReportScheduler(ctx context.Context) {
	run := func() {
		if _, err := s.RunComplianceReportsOnce(ctx); err != nil && ctx.Err() == nil && s.logger != nil {
			s.logger.Error("scheduled compliance report sweep failed", slog.String("error", err.Error()))
		}
	}
	run()
	ticker := time.NewTicker(complianceReportSweepInterval)
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

// RunComplianceReportsOnce performs at most 100 exact due-edge attempts. It
// rotates the starting tenant across sweeps, so one noisy tenant cannot starve
// every other tenant's signed reports.
func (s *Server) RunComplianceReportsOnce(ctx context.Context) (int, error) {
	if s == nil || s.store == nil || s.orch == nil || s.api == nil {
		return 0, errors.New("server: compliance report scheduler is not assembled")
	}
	s.reportSweepMu.Lock()
	defer s.reportSweepMu.Unlock()
	tenants, err := s.store.TenantsWithEnabledComplianceReportSchedules(ctx)
	if err != nil || len(tenants) == 0 {
		return 0, err
	}
	start := s.reportTenantOffset % len(tenants)
	attempted := 0
	now := time.Now().UTC()
	for visited := 0; visited < len(tenants) && attempted < complianceReportSweepLimit; visited++ {
		index := (start + visited) % len(tenants)
		tenantID := tenants[index]
		limit := complianceReportTenantBatch
		if remaining := complianceReportSweepLimit - attempted; remaining < limit {
			limit = remaining
		}
		due, err := s.store.ComplianceReportSchedulesDue(ctx, tenantID, now, limit)
		if err != nil {
			s.reportTenantOffset = (index + 1) % len(tenants)
			return attempted, err
		}
		for _, schedule := range due {
			processed, err := s.runComplianceReportDue(ctx, schedule, now)
			if err != nil {
				s.reportTenantOffset = (index + 1) % len(tenants)
				return attempted, err
			}
			if processed {
				attempted++
			}
		}
		s.reportTenantOffset = (index + 1) % len(tenants)
	}
	return attempted, nil
}

func (s *Server) runComplianceReportDue(ctx context.Context, selected store.ComplianceReportSchedule, now time.Time) (bool, error) {
	processed := false
	_, err := s.store.WithComplianceReportRunLock(ctx, selected.TenantID, selected.ID, selected.NextRunAt, func() error {
		// A pause or replacement can race the leader's read. Recheck the exact
		// due edge while holding its cross-replica production lock.
		schedule, err := s.store.GetComplianceReportSchedule(ctx, selected.TenantID, selected.ID)
		if err != nil {
			return err
		}
		if !schedule.Enabled || !schedule.NextRunAt.Equal(selected.NextRunAt) || now.Before(schedule.NextRunAt) {
			return nil
		}
		run, err := s.store.GetComplianceReportRunByDue(ctx, schedule.TenantID, schedule.ID, schedule.NextRunAt)
		if errors.Is(err, pgx.ErrNoRows) {
			run, err = s.orch.RecordComplianceReportRun(ctx, store.ComplianceReportRun{
				ID:       orchestrator.ComplianceReportRunID(schedule.TenantID, schedule.ID, schedule.NextRunAt),
				TenantID: schedule.TenantID, ScheduleID: schedule.ID, DueAt: schedule.NextRunAt,
				Framework: schedule.Framework, ReportType: schedule.ReportType,
				Status: "queued", CreatedAt: now,
			})
		}
		if err != nil {
			return err
		}
		if run.Status == "completed" || run.Status == "failed" ||
			(run.Status == "retrying" && run.NextAttemptAt.After(now)) {
			return nil
		}
		// Check all three possible durable outcomes of the next attempt. This
		// closes the JetStream append-ACK / PostgreSQL rollback gap before a
		// second call can ask the signer for the same due-edge report.
		if _, recovered, err := s.orch.RecoverComplianceReportNextTransition(ctx, run); err != nil {
			return err
		} else if recovered {
			processed = true
			return nil
		}
		processed = true
		return s.produceComplianceReportRun(ctx, schedule, run)
	})
	return processed, err
}

func (s *Server) produceComplianceReportRun(ctx context.Context, schedule store.ComplianceReportSchedule, run store.ComplianceReportRun) error {
	if s.reportArchive.Root == "" {
		return s.recordComplianceReportFailure(ctx, run, "archive_unavailable", false)
	}
	ref, digest, artifact, err := s.reportArchive.FindRun(run.TenantID, run.ID)
	if errors.Is(err, os.ErrNotExist) {
		artifact, err = s.api.BuildScheduledComplianceArtifact(ctx, run.TenantID, schedule, run.ID, time.Now().UTC())
		if err != nil {
			code := "producer_failed"
			if status.Code(err) == codes.Unavailable {
				code = "signer_unavailable"
			}
			return s.recordComplianceReportFailure(ctx, run, code, false)
		}
		if len(artifact) > reportarchive.MaxArtifactBytes {
			return s.recordComplianceReportFailure(ctx, run, "artifact_too_large", true)
		}
		if err := s.api.VerifyScheduledComplianceArtifact(artifact, run); err != nil {
			return s.recordComplianceReportFailure(ctx, run, "invalid_signature", true)
		}
		ref, digest, err = s.reportArchive.Put(run.TenantID, run.ID, artifact)
		if err != nil {
			if errors.Is(err, reportarchive.ErrArtifactTooLarge) {
				return s.recordComplianceReportFailure(ctx, run, "artifact_too_large", true)
			}
			return s.recordComplianceReportFailure(ctx, run, "archive_unavailable", false)
		}
	} else if err != nil {
		return s.recordComplianceReportFailure(ctx, run, "archive_corrupt", true)
	} else if err := s.api.VerifyScheduledComplianceArtifact(artifact, run); err != nil {
		return s.recordComplianceReportFailure(ctx, run, "archive_corrupt", true)
	}
	completed := run
	completed.Status = "completed"
	completed.Attempt++
	completed.NextAttemptAt = time.Time{}
	completed.ErrorCode = ""
	completed.ArtifactRef = ref
	completed.ArtifactDigest = digest
	completed.CompletedAt = time.Now().UTC()
	_, err = s.orch.RecordComplianceReportRun(ctx, completed)
	return err
}

func (s *Server) recordComplianceReportFailure(ctx context.Context, run store.ComplianceReportRun, code string, terminal bool) error {
	failed := run
	failed.Attempt++
	failed.ErrorCode = code
	failed.NextAttemptAt = time.Time{}
	if terminal || failed.Attempt >= 5 {
		failed.Status = "failed"
	} else {
		failed.Status = "retrying"
		failed.NextAttemptAt = time.Now().UTC().Add(time.Minute * time.Duration(1<<(failed.Attempt-1)))
	}
	if _, err := s.orch.RecordComplianceReportRun(ctx, failed); err != nil {
		return fmt.Errorf("server: record scheduled report failure: %w", err)
	}
	return nil
}
