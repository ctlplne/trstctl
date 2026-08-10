// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
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
		InstanceURL: sched.InstanceURL, TokenRef: sched.TokenRef, SNTable: sched.SNTable, Query: sched.Query,
		SubjectField: sched.SubjectField, ProfileField: sched.ProfileField,
		RequesterField: sched.RequesterField, JustificationField: sched.JustificationField,
		PageLimit: ticketIntakePageLimit,
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
			sched, due, err := s.store.TicketIntakeDue(ctx, tenantID, time.Now())
			if err != nil || !due {
				continue
			}
			s.dispatchTicketSyncJob(ctx, tenantID, sched)
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
	if err := ticketintake.ValidateReport(report); err != nil {
		return out, err
	}
	out.Read = len(report.Tickets)
	for _, ticket := range report.Tickets {
		sysID, subject, profile := strings.TrimSpace(ticket.SysID), strings.TrimSpace(ticket.Subject), strings.TrimSpace(ticket.Profile)
		if sysID == "" {
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
		ticketRef := intent.SNTable + ":" + sysID
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
			requester = "servicenow:" + intent.SNTable
		}
		if _, err := s.orch.OpenIssuanceRequestFromRelay(ctx, tenantID, resultKey, projections.IssuanceRequestOpened{
			Subject:       subject,
			Profile:       profile,
			Requester:     requester,
			Justification: strings.TrimSpace(ticket.Justification),
			Origin:        "servicenow",
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
	pending, err := s.store.HasPendingAgentJob(ctx, tenantID, agentJobKindTicketSync)
	if err != nil {
		s.logger.Warn("ticket relay dispatch: pending check failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	if pending {
		_ = s.store.MarkTicketIntakeRun(ctx, tenantID, sched.System, time.Now().UTC(),
			"a dispatched ticket.sync job is still waiting; if no network relay is enrolled and claiming, none will run it")
		return
	}
	payload, err := json.Marshal(ticketSyncIntent(sched))
	if err != nil {
		return
	}
	key := "ticket-sync:" + tenantID + ":" + time.Now().UTC().Format(time.RFC3339)
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: agentJobKindTicketSync, IdempotencyKey: key, Payload: payload,
			RequiredAgentRole: mtls.AgentRoleNetwork,
		})
		return err
	})
	if err != nil {
		s.logger.Warn("ticket relay dispatch failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	_ = s.store.MarkTicketIntakeRun(ctx, tenantID, sched.System, time.Now().UTC(), "")
}

func (s *Server) recordTicketSync(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
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
	res, err := s.ingestTicketReport(ctx, tenantID, idempotencyKey, intent, report)
	msg := ""
	if err != nil {
		msg = err.Error()
	} else {
		s.logger.Info("ticket relay intake complete", slog.String("tenant_id", tenantID), slog.String("agent", agentName),
			slog.Int("read", res.Read), slog.Int("opened", res.Opened), slog.Int("already", res.Already), slog.Int("skipped", res.Skipped))
	}
	if stampErr := s.store.MarkTicketIntakeRun(ctx, tenantID, "servicenow", time.Now().UTC(), msg); stampErr != nil && err == nil {
		err = stampErr
	}
	return err
}
