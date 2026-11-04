// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// acceptLateTerminalReceipt is reached only after normal certificate and signed
// terminal-statement verification. A retained claim binding proves the original
// recipient after the mutable lease has been reclaimed. Acceptance records that
// executor's completion only: no ingestion, target projection, outbox retirement,
// claim extension, credential redemption or automatic rollback may occur here.
func (a *agentService) acceptLateTerminalReceipt(ctx context.Context, info mtls.PeerCertInfo,
	agentID string, req *transport.ReportJobResultRequest, now time.Time) (*transport.ReportJobResultResponse, error) {
	destination, found, err := a.store.AgentJobAttemptBinding(ctx, info.TenantID, agentID, req.JobID, req.Attempt)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "original agent claim authority is unavailable")
	}
	if !found {
		return &transport.ReportJobResultResponse{Accepted: false}, nil
	}
	fields := map[string]any{
		"agent": info.CommonName, "job_id": req.JobID, "kind": destination,
		"attempt": req.Attempt, "outcome": strings.TrimSpace(req.Outcome), "current_state_applied": false,
	}
	a.attachJobReceipt(fields, info, req)
	if a.log == nil {
		return nil, status.Error(codes.Unavailable, "signed job receipt audit is unavailable")
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return nil, status.Error(codes.Internal, "signed job receipt audit could not be encoded")
	}
	err = a.recordVerifiedReceiptWithAudit(ctx, info, req, destination, now, func(ctx context.Context, receipt store.AgentJobReceipt) (store.AgentJobReceipt, error) {
		return a.retainLateReceipt(ctx, events.Event{Type: "agent.job.receipt.reconciled", TenantID: info.TenantID, Data: body}, receipt)
	})
	if errors.Is(err, store.ErrAgentJobReceiptConflict) {
		refusal, err := json.Marshal(map[string]any{
			"agent": info.CommonName, "job_id": req.JobID, "attempt": req.Attempt,
			"reason": "terminal observation conflicts with recorded receipt",
		})
		if err != nil {
			return nil, status.Error(codes.Internal, "receipt refusal could not be encoded")
		}
		if _, err := a.log.Append(ctx, events.Event{Type: "agent.job.receipt.conflict", TenantID: info.TenantID, Data: refusal}); err != nil {
			return nil, status.Error(codes.Unavailable, "receipt refusal audit is unavailable")
		}
		return &transport.ReportJobResultResponse{}, nil
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, "signed job receipt could not be stored; retry the same report")
	}
	// A255: a recalled gateway session's job is cancelled before its gateway
	// can report, so the gateway's report that it ended the session arrives
	// here. It is that session's termination acknowledgement: recorded once
	// it matches the job this agent held at this attempt.
	if destination == relay.KindAccessGatewaySession && strings.TrimSpace(req.Outcome) == transport.JobOutcomeExecuted &&
		a.recordGatewaySessionEnded != nil {
		payload, key, err := a.store.AgentJobPayload(ctx, info.TenantID, req.JobID)
		if err != nil {
			return nil, status.Error(codes.Unavailable, "gateway session job is unavailable")
		}
		var intent accessgateway.SessionIntent
		if json.Unmarshal(payload, &intent) != nil || key != accessgateway.JobKey(intent.SessionID) ||
			validateGatewaySessionReport(payload, req.Detail) != nil {
			return &transport.ReportJobResultResponse{ReceiptRecorded: true}, nil
		}
		if err := a.recordGatewaySessionEnded(ctx, info.TenantID, payload, req.Detail, req.Attempt); err != nil {
			return nil, status.Error(codes.Unavailable, "gateway session end could not be recorded; retry the same report")
		}
	}
	return &transport.ReportJobResultResponse{ReceiptRecorded: true}, nil
}
