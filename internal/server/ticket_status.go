// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

// ServiceNow change-request approvals (P13). A request intake opened from a
// change request waits on that change's approval: each intake pass of a
// change_request schedule queues one relay read of the approval and state of
// the requests still waiting (at most 100), and the relay's checked report
// approves or denies each matching request once — approved or rejected in
// ServiceNow, nothing else. The decision is attributed to the change, so it
// cannot be mistaken for a reviewer in trstctl.

// dispatchTicketStatusJob queues one approval read for a ServiceNow
// change_request schedule, one in flight per schedule.
func (s *Server) dispatchTicketStatusJob(ctx context.Context, tenantID string, sched store.TicketIntakeSchedule) {
	if sched.System != ticketintake.SystemServiceNow || sched.SNTable != ticketintake.StatusTable || !sched.Enabled {
		return
	}
	pending, err := s.store.HasPendingTicketStatusJob(ctx, tenantID, sched.Name)
	if err != nil || pending {
		return
	}
	waiting, err := s.store.IssuanceRequestsAwaitingTicket(ctx, tenantID, ticketintake.StatusTable, ticketintake.MaxStatusTickets)
	if err != nil || len(waiting) == 0 {
		return
	}
	refs := make([]string, 0, len(waiting))
	for _, r := range waiting {
		refs = append(refs, strings.TrimPrefix(r.TicketRef, ticketintake.StatusTable+":"))
	}
	intent := ticketintake.StatusIntent{Schedule: ticketintake.ScheduleName(sched.Name), StatusID: uuid.NewString(),
		InstanceURL: sched.InstanceURL, TokenRef: sched.TokenRef, SNTable: sched.SNTable, SourceRefs: refs}
	if _, err := ticketintake.StatusEndpoint(intent); err != nil {
		s.logger.Warn("ticket status dispatch: intent refused", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return
	}
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{TenantID: tenantID, Destination: relay.KindTicketStatus,
			IdempotencyKey: "ticket-status:" + tenantID + ":" + intent.Schedule + ":" + intent.StatusID, Payload: payload,
			RequiredAgentRole: "network"})
		return err
	}); err != nil {
		s.logger.Warn("ticket status dispatch failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
	}
}

// recordTicketStatus decides, from a relay's checked report, each waiting
// request whose change ServiceNow approved or rejected. Reading the same
// approval again records nothing new.
func (a *agentService) recordTicketStatus(ctx context.Context, tenantID string, payload []byte, detail string) error {
	var intent ticketintake.StatusIntent
	if err := decodeStrictJSON(payload, &intent); err != nil {
		return fmt.Errorf("server: decode durable ticket status intent: %w", err)
	}
	if len(detail) > maxStructuredSyncReportBytes {
		return fmt.Errorf("server: ticket status report exceeds the %d-byte bound", maxStructuredSyncReportBytes)
	}
	var report ticketintake.StatusReport
	if err := decodeStrictJSON([]byte(detail), &report); err != nil {
		return fmt.Errorf("server: decode ticket status report: %w", err)
	}
	if err := ticketintake.ValidateStatusReport(intent, report); err != nil {
		return err
	}
	if a.orch == nil || a.store == nil {
		return errors.New("ticket status receiver is not configured")
	}
	for _, ticket := range report.Tickets {
		var to, verb string
		switch ticket.Approval {
		case ticketintake.ApprovalApproved:
			to, verb = issuancerequest.StateApproved, "approved"
		case ticketintake.ApprovalRejected:
			to, verb = issuancerequest.StateDenied, "rejected"
		default:
			continue
		}
		request, found, err := a.store.IssuanceRequestByTicket(ctx, tenantID, ticketintake.StatusTable+":"+ticket.SourceRef)
		if err != nil {
			return err
		}
		if !found || request.Origin != ticketintake.SystemServiceNow {
			continue
		}
		change := ticket.Number
		if change == "" {
			change = ticket.SourceRef
		}
		if _, err := a.orch.DecideIssuanceRequestFromTicket(ctx, tenantID, request.ID, to,
			"servicenow:change_request:"+change, "change "+change+" was "+verb+" in ServiceNow"); err != nil {
			return err
		}
	}
	return nil
}
