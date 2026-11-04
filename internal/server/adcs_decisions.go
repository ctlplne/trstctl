// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Decisions on pending AD CS requests (N1), on the server side: the issuer's
// relay route comes from its adcs configuration (the relay that already
// revokes for it, A162), the decision waits on an exact operation approval,
// and the relay's checked report records what the CA now holds.

// adcsDecisionApprovalTTL bounds how long an approved decision may wait to be
// executed.
const adcsDecisionApprovalTTL = 24 * time.Hour

// adcsDecisionRoute is the issuer's AD CS relay route for this tenant.
func (s *Server) adcsDecisionRoute(tenantID, issuerID string) (ADCSRevocationRelay, error) {
	if s.externalCAs == nil {
		return ADCSRevocationRelay{}, api.ErrADCSDecisionUnavailable
	}
	entry, ok := s.externalCAs.byID[strings.TrimSpace(issuerID)]
	if !ok || (entry.tenantID != "" && entry.tenantID != tenantID) || entry.adcsRevocation.Relay == "" ||
		!relay.ValidCAConfig(entry.adcsRevocation.CAConfig) {
		return ADCSRevocationRelay{}, api.ErrADCSDecisionUnavailable
	}
	return entry.adcsRevocation, nil
}

// adcsRequestResourceID names one request at one CA through one issuer.
func adcsRequestResourceID(issuerID, caConfig string, requestID int) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("adcs-request\x00"+issuerID+"\x00"+caConfig+"\x00"+strconv.Itoa(requestID))).String()
}

func adcsDecisionToState(decision string) string {
	if decision == relay.ADCSDecisionApprove {
		return "issued"
	}
	return "denied"
}

// RequestADCSDecisionApproval asks reviewers to approve one exact decision.
func (s *Server) RequestADCSDecisionApproval(ctx context.Context, tenantID, requester, issuerID string, requestID int,
	input api.ADCSDecisionRequest) (api.ADCSDecisionApproval, error) {
	route, err := s.adcsDecisionRoute(tenantID, issuerID)
	if err != nil {
		return api.ADCSDecisionApproval{}, err
	}
	required := s.adcsDecisionApprovals
	if required <= 0 {
		required = defaultRequiredApprovals
	}
	request, err := s.orch.EnsureOperationApprovalRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "adcs_request", ResourceID: adcsRequestResourceID(issuerID, route.CAConfig, requestID),
		ResourceName: fmt.Sprintf("%s request %d", route.CAConfig, requestID), Action: input.Decision, Requester: requester,
		FromState: "pending", ToState: adcsDecisionToState(input.Decision), TargetVersion: 1, Reason: input.Reason,
		EvidenceRefs: []string{"adcs-request:" + issuerID + ":" + strconv.Itoa(requestID)}, RequiredApprovals: required,
		TTL: adcsDecisionApprovalTTL,
	})
	if err != nil {
		return api.ADCSDecisionApproval{}, err
	}
	return api.ADCSDecisionApproval{IssuerID: issuerID, CAConfig: route.CAConfig, RequestID: requestID, Decision: input.Decision,
		Reason: input.Reason, ApprovalRequestID: request.ID, ApprovalIntentDigest: request.IntentDigest, Status: request.Status,
		RequiredApprovals: request.RequiredApprovals, ApprovalCount: request.ApprovalCount, ExpiresAt: request.ExpiresAt}, nil
}

// QueueADCSDecision executes an approved decision: it queues one relay job,
// spending the approval.
func (s *Server) QueueADCSDecision(ctx context.Context, tenantID, requester, issuerID string, requestID int,
	input api.ADCSDecisionStart) (store.ADCSDecision, error) {
	route, err := s.adcsDecisionRoute(tenantID, issuerID)
	if err != nil {
		return store.ADCSDecision{}, err
	}
	id, err := uuid.Parse(strings.TrimSpace(input.ApprovalRequestID))
	if err != nil || id == uuid.Nil {
		return store.ADCSDecision{}, store.ErrApprovalRequestNotFound
	}
	request, err := s.store.GetOperationApproval(ctx, tenantID, id.String())
	if err != nil {
		return store.ADCSDecision{}, err
	}
	if request.IntentDigest != input.ApprovalIntentDigest || request.Requester != requester || request.ResourceKind != "adcs_request" ||
		request.ResourceID != adcsRequestResourceID(issuerID, route.CAConfig, requestID) ||
		(request.Action != relay.ADCSDecisionApprove && request.Action != relay.ADCSDecisionDeny) {
		return store.ADCSDecision{}, store.ErrApprovalDigestMismatch
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		return store.ADCSDecision{}, err
	}
	queued := projections.ADCSDecisionQueued{ID: orchestrator.ADCSDecisionID(tenantID, use.RequestID), IssuerID: issuerID,
		CAConfig: route.CAConfig, RequestID: requestID, Decision: use.Action, RelayAgentID: agentRowID(tenantID, route.Relay), Approval: use}
	if err := s.orch.QueueADCSDecision(ctx, tenantID, queued); err != nil {
		return store.ADCSDecision{}, err
	}
	return s.store.GetADCSDecision(ctx, tenantID, queued.ID)
}

// recordADCSDecisionResult checks a relay's decision report against its queued
// job — the exact relay, the same request, CA and decision, read back with the
// decided disposition — and records what the CA now holds.
func (a *agentService) recordADCSDecisionResult(ctx context.Context, tenantID, agentName string, payload []byte, detail string) error {
	var intent relay.ADCSDecideIntent
	if err := decodeStrictJSON(payload, &intent); err != nil {
		return fmt.Errorf("server: decode durable AD CS decision: %w", err)
	}
	if intent.RequiredAgentID == "" || intent.RequiredAgentID != agentRowID(tenantID, agentName) {
		return errors.New("server: an AD CS decision result requires the issuer's exact relay")
	}
	var report relay.ADCSDecideReport
	if err := decodeStrictJSON([]byte(detail), &report); err != nil {
		return fmt.Errorf("server: decode AD CS decision report: %w", err)
	}
	if err := relay.ValidateADCSDecideReport(intent, report); err != nil {
		return err
	}
	if a.orch == nil {
		return errors.New("AD CS decision result receiver is not configured")
	}
	return a.orch.RecordADCSDecided(ctx, tenantID, projections.ADCSDecided{ID: intent.ID, Disposition: report.Disposition, Serial: report.Serial})
}
