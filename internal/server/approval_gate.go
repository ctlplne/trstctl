// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

// EXC-WIRE-03 — server-side construction of the served policy / RA-separation /
// dual-control gate (api.MutationGate) and the event-store-backed approval recorder
// it consults. Until now the OPA/Rego default-deny engine (internal/policy), the RA
// scope split, and dual-control approval (internal/approval) were library-only
// (SEC-002, SEC-005, CORRECT-003); the served mint was reachable without them
// (RED-004). buildMutationGate assembles them from Deps so the running cmd/trstctl
// binary enforces them on the mutating issue/deploy/revoke path. Everything here is
// tenant-scoped (AN-1, the store enforces RLS), fail-closed, and — for policy —
// audited (AN-2) on the policy bulkhead (AN-7).

// defaultRequiredApprovals is the dual-control default (matches internal/approval).
const defaultRequiredApprovals = 2

// buildMutationGate constructs the served mutation gate and (when dual control is
// on) its approval recorder from Deps. It returns a permissive zero gate and a nil
// recorder when nothing is configured, so an unconfigured deployment keeps the prior
// served behavior. A non-compiling policy module is a hard error (the platform must
// not serve without an enforceable policy when the gate is on).
type approvalOutbox interface {
	EnqueueIfAbsent(context.Context, pgx.Tx, orchestrator.Entry) (bool, error)
}

func buildMutationGate(d Deps, bulk *bulkhead.Set, outbox approvalOutbox, orch *orchestrator.Orchestrator) (api.MutationGate, api.ApprovalRecorder, error) {
	// Profile selection is part of issuance authority even when neither OPA nor
	// the ABAC overlay is enabled. Keeping it on the base gate lets the served
	// handler resolve the configured revision, apply its requires_approval bit,
	// and pin its TTL before any lifecycle event is appended.
	gate := api.MutationGate{Profile: d.DefaultProfile}

	if d.EnablePolicyGate {
		var pool *bulkhead.Pool
		if bulk != nil {
			pool = bulk.Pool(bulkhead.SubsystemPolicy) // AN-7: the engine's own pool
		}
		eng, err := policy.NewLive(policy.Config{
			Module: d.PolicyModule, // empty → policy.BaseModule (default-deny)
			Pool:   pool,
			Log:    d.Log, // AN-2: every decision is an audited event
		})
		if err != nil {
			return api.MutationGate{}, nil, err
		}
		gate.Policy = eng
		// Feed the served-bound profile name into the policy input so a Rego rule can
		// require a bound profile (the base policy denies issue/deploy with an empty
		// profile). This ties the policy gate to PKIGOV-002's profile model.
	}
	if d.EnableABAC {
		var pool *bulkhead.Pool
		if bulk != nil {
			pool = bulk.Pool(bulkhead.SubsystemPolicy)
		}
		eng, err := policy.NewABAC(policy.ABACConfig{
			Module: d.ABACModule,
			Pool:   pool,
			Log:    d.Log,
		})
		if err != nil {
			return api.MutationGate{}, nil, err
		}
		gate.ABAC = eng
		gate.ABACEnvironment = d.ABACEnvironment
	}

	var recorder api.ApprovalRecorder
	if d.Store != nil {
		if d.RequireApproval && outbox == nil {
			return api.MutationGate{}, nil, fmt.Errorf("server: dual control requires the transactional notification outbox")
		}
		required := d.RequiredApprovals
		if required <= 0 {
			required = defaultRequiredApprovals
		}
		if orch == nil {
			return api.MutationGate{}, nil, fmt.Errorf("server: approval authority requires the event-sourced orchestrator")
		}
		gate.Checker = storeApprovalChecker{store: d.Store, orch: orch, required: required}
		recorder = storeApprovalRecorder{store: d.Store, orch: orch}
		if d.RequireApproval {
			gate.RequireApproval = true
		}
	}

	return gate, recorder, nil
}

// storeApprovalChecker implements the exact event-sourced approval contract. The
// legacy boolean method deliberately fails closed; AuthorizeApproval is the only
// method that can return request/digest/version-bound candidate authority. The
// eventual command projector must consume that authority atomically with the
// protected mutation and outbox intent.
type storeApprovalChecker struct {
	store    *store.Store
	orch     *orchestrator.Orchestrator
	required int
}

// IsApproved is the legacy resource/action-only seam. It deliberately cannot
// create or return authority: without request ID, digest, target version, and
// evidence a caller could turn a standing boolean into a reusable grant.
func (c storeApprovalChecker) IsApproved(context.Context, string, string, string, string) (bool, string) {
	return false, "legacy approval checks cannot authorize; exact single-use authority is required"
}

// AuthorizeApproval creates (only from the requester-side operation attempt) or
// reads the immutable request for this exact intent. It never records a review.
// A returned authority is still only a candidate: the target command must embed
// and consume it in its own event/projection/outbox transaction.
func (c storeApprovalChecker) AuthorizeApproval(ctx context.Context, intent api.ApprovalIntent) (api.ApprovalAuthority, bool, string) {
	required := intent.RequiredApprovals
	if required <= 0 {
		required = c.required
	}
	if required <= 0 {
		required = defaultRequiredApprovals
	}
	request, err := c.orch.EnsureOperationApprovalRequest(ctx, intent.TenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: intent.ResourceKind, ResourceID: intent.ResourceID,
		ResourceName: intent.ResourceName, Action: intent.Action, Requester: intent.Requester,
		FromState: intent.FromState, ToState: intent.ToState, TargetVersion: intent.TargetVersion,
		Reason: intent.Reason, EvidenceRefs: intent.EvidenceRefs,
		RequiredApprovals: required, TTL: intent.TTL,
	})
	if err != nil {
		return api.ApprovalAuthority{}, false, "could not record the immutable approval request"
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		return api.ApprovalAuthority{}, false, "the immutable approval request has invalid issuance evidence"
	}
	authority := api.ApprovalAuthority{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Requester: request.Requester, ResourceKind: request.ResourceKind,
		ResourceID: request.ResourceID, Action: request.Action,
		FromState: request.FromState, ToState: request.ToState,
		TargetVersion: request.TargetVersion, RequiredApprovals: request.RequiredApprovals,
		Reason: request.Reason, EvidenceRefs: append([]string(nil), request.EvidenceRefs...),
		Issuance:    use.Issuance,
		Disposition: operationApprovalDisposition(request, time.Now().UTC()),
	}
	if reason := operationApprovalRequesterDenialReason(request, time.Now().UTC()); reason != "" {
		return authority, false, reason
	}
	return authority, true, ""
}

func operationApprovalDisposition(request store.OperationApprovalRequest, now time.Time) api.ApprovalDisposition {
	switch request.Status {
	case store.ApprovalStatusConsumed:
		return api.ApprovalDispositionConsumed
	case store.ApprovalStatusSuperseded:
		return api.ApprovalDispositionSuperseded
	case store.ApprovalStatusDenied:
		return api.ApprovalDispositionDenied
	case store.ApprovalStatusExpired:
		return api.ApprovalDispositionExpired
	}
	if !now.Before(request.ExpiresAt) {
		return api.ApprovalDispositionExpired
	}
	if request.Status == store.ApprovalStatusApproved && request.ApprovalCount >= request.RequiredApprovals {
		return api.ApprovalDispositionApproved
	}
	return api.ApprovalDispositionPending
}

// operationApprovalRequesterDenialReason preserves the store's terminal-state
// vocabulary at the requester gate. Reviewers and command callers therefore see
// whether waiting could help (pending) or whether they must create a new exact
// intent (expired/superseded/denied/consumed). The request ID and digest make the
// message traceable without revealing tenant or secret material.
func operationApprovalRequesterDenialReason(request store.OperationApprovalRequest, now time.Time) string {
	prefix := fmt.Sprintf("approval request %s (%s)", request.ID, request.IntentDigest)
	switch request.Status {
	case store.ApprovalStatusConsumed:
		return prefix + " already consumed"
	case store.ApprovalStatusSuperseded:
		return prefix + " superseded because its target or immutable intent drifted"
	case store.ApprovalStatusDenied:
		return prefix + " denied"
	case store.ApprovalStatusExpired:
		return prefix + " expired"
	}
	if !now.Before(request.ExpiresAt) {
		return prefix + " expired"
	}
	if request.Status == store.ApprovalStatusApproved && request.ApprovalCount >= request.RequiredApprovals {
		return ""
	}
	remaining := request.RequiredApprovals - request.ApprovalCount
	if remaining < 0 {
		remaining = 0
	}
	if request.Status == store.ApprovalStatusPending || request.Status == store.ApprovalStatusApproved {
		return fmt.Sprintf("%s awaits %d distinct approval(s)", prefix, remaining)
	}
	return fmt.Sprintf("%s cannot authorize while status is %s", prefix, request.Status)
}

// storeApprovalRecorder implements api.ApprovalRecorder over the store's issuance
// approval tables. A distinct approver records their approval through the served
// POST /api/v1/identities/{id}/approvals endpoint (which requires certs:issue, the
// RA split). The store rejects a self-approval (approver == requester) and an
// anonymous approver. Tenant-scoped (AN-1).
type storeApprovalRecorder struct {
	store *store.Store
	orch  *orchestrator.Orchestrator
}

// ValidateApprovalRequest is the read-only HTTP preflight used before the API
// reserves an idempotency key. RLS makes an absent and cross-tenant request the
// same result, and a wrong digest is deliberately mapped to that same 404. The
// orchestrator repeats these checks under locks before appending the decision.
func (r storeApprovalRecorder) ValidateApprovalRequest(ctx context.Context, tenantID string, decision api.ApprovalDecisionCommand) (api.ApprovalRequestRecord, error) {
	request, err := r.store.GetOperationApproval(ctx, tenantID, decision.RequestID)
	if err != nil {
		return api.ApprovalRequestRecord{}, err
	}
	if request.IntentDigest != decision.IntentDigest ||
		decision.ExpectedResourceKind != "" && decision.ExpectedResourceKind != request.ResourceKind ||
		decision.ExpectedResourceID != "" && decision.ExpectedResourceID != request.ResourceID ||
		decision.ExpectedAction != "" && decision.ExpectedAction != request.Action {
		return api.ApprovalRequestRecord{}, store.ErrApprovalDigestMismatch
	}
	return approvalRequestRecord(request), nil
}

// ListApprovalRequests returns only genuine event-projected request objects. Reviewer
// actions never create a parent request; RecordApproval below can only decide an
// already-existing exact request ID and digest.
func (r storeApprovalRecorder) ListApprovalRequests(ctx context.Context, tenantID string, options api.ApprovalRequestListOptions) ([]api.ApprovalRequestRecord, error) {
	rows, err := r.store.ListOperationApprovalsPage(ctx, tenantID, store.OperationApprovalListOptions{
		Status: options.Status, AfterCreatedAt: options.AfterCreatedAt, AfterID: options.AfterID, Limit: options.Limit,
		Visibility: store.OperationApprovalDomainVisibility{
			CertificateOperations: options.CertificateOperations,
			SecretOperations:      options.SecretOperations,
			ManagedKeyOperations:  options.ManagedKeyOperations,
		},
	})
	if err != nil {
		return nil, err
	}
	out := make([]api.ApprovalRequestRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, approvalRequestRecord(row))
	}
	return out, nil
}

func (r storeApprovalRecorder) RecordApproval(ctx context.Context, tenantID string, decision api.ApprovalDecisionCommand) (api.ApprovalRequestRecord, error) {
	row, err := r.orch.RecordOperationApprovalDecision(ctx, tenantID, orchestrator.OperationApprovalDecision{
		RequestID: decision.RequestID, IntentDigest: decision.IntentDigest,
		Approver: decision.Approver, Decision: decision.Decision, Reason: decision.Reason,
		ExpectedResourceKind: decision.ExpectedResourceKind,
		ExpectedResourceID:   decision.ExpectedResourceID, ExpectedAction: decision.ExpectedAction,
	})
	if err != nil {
		return api.ApprovalRequestRecord{}, err
	}
	return approvalRequestRecord(row), nil
}

func approvalRequestRecord(row store.OperationApprovalRequest) api.ApprovalRequestRecord {
	return api.ApprovalRequestRecord{
		ID: row.ID, IntentDigest: row.IntentDigest, ResourceID: row.ResourceID,
		ResourceName: row.ResourceName, ResourceKind: row.ResourceKind,
		Action: row.Action, Requester: row.Requester, FromState: row.FromState,
		ToState: row.ToState, TargetVersion: strconv.FormatUint(row.TargetVersion, 10),
		Reason: row.Reason, EvidenceRefs: append([]string(nil), row.EvidenceRefs...),
		ApprovalCount: row.ApprovalCount, RequiredApprovals: row.RequiredApprovals,
		Status: row.Status, CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: row.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
}
