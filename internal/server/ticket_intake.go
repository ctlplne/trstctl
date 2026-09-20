// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

// Ticket-driven issuance-request intake (epic I3).
//
// The ticket the requester already filed in the ITSM BECOMES the request:
// origin says which system, ticket_ref names the exact record, and the whole
// existing lifecycle — approval with separation of duties, denial with a
// reason, expiry — applies unchanged. The intake opens requests; it decides
// nothing, exactly as the relay reads observe and decide nothing.

const (
	// ticketIntakeInterval is detection latency for due schedules.
	ticketIntakeInterval = time.Minute
	// ticketIntakePageLimit bounds one sweep's read (AN-7).
	ticketIntakePageLimit = 100
	// ticketIntakeRequestTTL is how long an intake-opened request lives
	// undecided before the existing expiry sweep closes it. Tickets carry
	// their own urgency; a stale unapproved request is the queue's problem to
	// surface, not the intake's to guess about.
	ticketIntakeRequestTTL = 7 * 24 * time.Hour
	// agentJobKindTicketSync is the relay-executed ITSM observation.
	agentJobKindTicketSync = "ticket.sync"
)

// TicketIntakeResult is what one sweep did, and what it refused to do.
type TicketIntakeResult struct {
	Read    int
	Opened  int
	Already int
	// Skipped counts tickets missing the mapped subject or profile — reported,
	// never guessed at.
	Skipped int
}

func ticketSyncIntent(sched store.TicketIntakeSchedule) ticketintake.SyncIntent {
	return ticketintake.SyncIntent{
		System: sched.System, InstanceURL: sched.InstanceURL, TokenRef: sched.TokenRef,
		SNTable: sched.SNTable, JiraProject: sched.JiraProject, Query: sched.Query,
		SubjectField: sched.SubjectField, ProfileField: sched.ProfileField,
		RequesterField: sched.RequesterField, JustificationField: sched.JustificationField,
		PageLimit: ticketIntakePageLimit, SweepID: sched.CurrentSweepID,
		Cursor: sched.Cursor, ReadCount: sched.ReadCount, ExpectedCount: sched.ExpectedCount,
	}
}

// RunTicketIntake is the leader-only ticker.
func (s *Server) RunTicketIntake(ctx context.Context) {
	if s.store == nil || s.orch == nil {
		return
	}
	sweep := func() {
		tenants, err := s.store.TenantsWithEnabledTicketIntake(ctx)
		if err != nil {
			s.logger.Warn("ticket intake: list tenants failed", slog.String("error", err.Error()))
			return
		}
		for _, tenantID := range tenants {
			due, err := s.store.TicketIntakeDueSchedules(ctx, tenantID, time.Now())
			if err != nil {
				continue
			}
			for _, sched := range due {
				s.dispatchTicketSyncJob(ctx, tenantID, sched)
			}
		}
	}
	sweep()
	tk := time.NewTicker(ticketIntakeInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			sweep()
		}
	}
}

// ingestTicketReport opens requests from a signed, typed relay observation. It
// contains no network client and receives no credential material.
func (s *Server) ingestTicketReport(ctx context.Context, tenantID, resultKey string, intent ticketintake.SyncIntent, report ticketintake.SyncReport) (TicketIntakeResult, error) {
	var out TicketIntakeResult
	if err := ticketintake.ValidateReport(intent, report); err != nil {
		return out, err
	}
	out.Read = len(report.Tickets)
	for _, ticket := range report.Tickets {
		sourceRef, subject, profile := strings.TrimSpace(ticket.SourceRef), strings.TrimSpace(ticket.Subject), strings.TrimSpace(ticket.Profile)
		if sourceRef == "" {
			out.Skipped++
			continue
		}
		if subject == "" || profile == "" {
			// The mapped field is empty on this ticket. Guessing a subject
			// from a description column would open requests for prose;
			// skipping AND COUNTING is what lets an operator see the mapping
			// is wrong rather than wondering where their tickets went.
			out.Skipped++
			continue
		}
		ticketKey := strings.TrimSpace(ticket.ExternalKey)
		if ticketKey == "" {
			ticketKey = sourceRef
		}
		ticketRef := intent.System + ":" + ticketKey
		if intent.System == ticketintake.SystemServiceNow {
			ticketRef = intent.SNTable + ":" + sourceRef
		}
		exists, err := s.store.IssuanceRequestExistsForTicket(ctx, tenantID, ticketRef)
		if err != nil {
			return out, err
		}
		if exists {
			// One ticket, one request, however many polls see it. A denied
			// request does NOT reopen: the denial was the answer to that
			// ticket, and a fresh ask needs a fresh ticket.
			out.Already++
			continue
		}
		requester := strings.TrimSpace(ticket.Requester)
		if requester == "" {
			// The lifecycle's separation-of-duties check needs a requester.
			// The ticket system is the closest attributable actor when the
			// ticket does not name one.
			requester = intent.System + ":" + ticketKey
		}
		if _, err := s.orch.OpenIssuanceRequestFromRelay(ctx, tenantID, resultKey, projections.IssuanceRequestOpened{
			Subject:       subject,
			Profile:       profile,
			Requester:     requester,
			Justification: strings.TrimSpace(ticket.Justification),
			Origin:        intent.System,
			TicketRef:     ticketRef,
			ExpiresAt:     report.ObservedAt.UTC().Add(ticketIntakeRequestTTL),
		}); err != nil {
			return out, err
		}
		out.Opened++
	}
	return out, nil
}

func (s *Server) dispatchTicketSyncJob(ctx context.Context, tenantID string, sched store.TicketIntakeSchedule) {
	pending, err := s.store.HasPendingTicketSyncJob(ctx, tenantID, sched.System)
	if err != nil {
		s.logger.Warn("ticket relay dispatch: pending check failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	if pending {
		// An in-flight page remains honestly incomplete. Queueing or waiting is
		// not a successful provider observation and cannot stamp last_run_at.
		return
	}
	intent := ticketSyncIntent(sched)
	now := time.Now().UTC()
	if intent.SweepID != "" && !sched.CoverageComplete {
		err = s.orch.ResumeTicketIntakeSweep(ctx, tenantID, intent)
	} else {
		intent.SweepID = uuid.NewString()
		intent.Cursor = ""
		intent.ReadCount = 0
		intent.ExpectedCount = nil
		err = s.orch.QueueTicketIntakeSweep(ctx, tenantID, intent, now)
	}
	if err != nil {
		s.logger.Warn("ticket relay dispatch failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
}

func (s *Server) recordTicketSync(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	return s.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		return s.recordTicketSyncLocked(lockCtx, tenantID, agentName, idempotencyKey, jobPayload, reportJSON)
	})
}

func (s *Server) recordTicketSyncLocked(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	var intent ticketintake.SyncIntent
	if err := json.Unmarshal(jobPayload, &intent); err != nil {
		return fmt.Errorf("server: decode durable ticket sync intent: %w", err)
	}
	if _, err := ticketintake.Endpoint(intent); err != nil {
		return fmt.Errorf("server: validate durable ticket sync intent: %w", err)
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return fmt.Errorf("server: ticket relay report exceeds the %d-byte bound", maxStructuredSyncReportBytes)
	}
	var report ticketintake.SyncReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		return fmt.Errorf("server: decode ticket relay report: %w", err)
	}
	if err := ticketintake.ValidateReport(intent, report); err != nil {
		return err
	}
	res, err := s.ingestTicketReport(ctx, tenantID, idempotencyKey, intent, report)
	if err != nil {
		return err
	}
	var next *ticketintake.SyncIntent
	if !report.Complete {
		continued := intent
		continued.Cursor = report.NextCursor
		continued.ReadCount = report.ReadCount
		continued.ExpectedCount = report.ExpectedCount
		next = &continued
	}
	if err := s.orch.RecordTicketIntakeSweepPage(ctx, tenantID, idempotencyKey, projections.TicketIntakeSweepPageObserved{
		Intent: intent, ObservedAt: report.ObservedAt, SourceRefs: report.SourceRefs,
		ReadCount: report.ReadCount, ExpectedCount: report.ExpectedCount,
		Complete: report.Complete, NextCursor: report.NextCursor,
		Eligible: res.Read - res.Skipped, Skipped: res.Skipped, NextIntent: next,
	}); err != nil {
		return err
	}
	s.logger.Info("ticket relay intake page committed", slog.String("tenant_id", tenantID),
		slog.String("agent", agentName), slog.String("system", intent.System),
		slog.String("sweep_id", intent.SweepID), slog.Int("read", res.Read),
		slog.Int("opened", res.Opened), slog.Int("already", res.Already),
		slog.Int("skipped", res.Skipped), slog.Bool("complete", report.Complete))
	return nil
}

func (s *Server) recordTicketSyncFailure(
	ctx context.Context,
	tenantID, idempotencyKey string,
	payload []byte,
	attempt int,
	failedAt time.Time,
	detail string,
) error {
	var intent ticketintake.SyncIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return fmt.Errorf("server: decode failed ticket sync intent: %w", err)
	}
	return s.orch.RecordTicketIntakeSweepFailure(ctx, tenantID, idempotencyKey, attempt, intent, failedAt, detail)
}
