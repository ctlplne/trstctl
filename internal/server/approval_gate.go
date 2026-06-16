package server

import (
	"context"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
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
func buildMutationGate(d Deps, bulk *bulkhead.Set) (api.MutationGate, api.ApprovalRecorder, error) {
	gate := api.MutationGate{}

	if d.EnablePolicyGate {
		var pool *bulkhead.Pool
		if bulk != nil {
			pool = bulk.Pool(bulkhead.SubsystemPolicy) // AN-7: the engine's own pool
		}
		eng, err := policy.New(policy.Config{
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
		gate.Profile = d.DefaultProfile
	}

	var recorder api.ApprovalRecorder
	if d.RequireApproval {
		required := d.RequiredApprovals
		if required <= 0 {
			required = defaultRequiredApprovals
		}
		gate.RequireApproval = true
		gate.Checker = storeApprovalChecker{store: d.Store, required: required}
		recorder = storeApprovalRecorder{store: d.Store, required: required}
	}

	return gate, recorder, nil
}

// storeApprovalChecker implements api.ApprovalChecker over the store's issuance
// approval tables. It is the predicate the gate consults for a privileged
// (issue/revoke) transition: it records (idempotently) that the requester's action
// awaits approval — capturing the requester so they can never count as their own
// approver — and then reports whether `required` DISTINCT approvers (excluding the
// requester) have approved. Tenant-scoped (AN-1); fail-closed (any store error or an
// insufficient count denies).
type storeApprovalChecker struct {
	store    *store.Store
	required int
}

// IsApproved reports whether the (tenant, resource, action) has the required number
// of distinct-approver approvals, excluding the requester (so a self-approval can
// never satisfy it). It first opens the approval request (idempotently) capturing
// the requester, so a distinct approver's later approval is checked against them.
func (c storeApprovalChecker) IsApproved(ctx context.Context, tenantID, resource, action, requester string) (bool, string) {
	required := c.required
	if required <= 0 {
		required = defaultRequiredApprovals
	}
	// Record that this requester's privileged action awaits approval (idempotent;
	// preserves the original requester on a retry). Capturing the requester is what
	// lets the store reject a self-approval and lets HasDistinctApproval exclude them.
	if err := c.store.OpenIssuanceApprovalRequest(ctx, tenantID, resource, action, requester, required); err != nil {
		return false, "could not record the approval request"
	}
	ok, err := c.store.HasDistinctApproval(ctx, tenantID, resource, action, requester, required)
	if err != nil {
		return false, "could not evaluate approvals"
	}
	if !ok {
		return false, "this action has not been approved by the required number of distinct approvers (the requester cannot self-approve)"
	}
	return true, ""
}

// storeApprovalRecorder implements api.ApprovalRecorder over the store's issuance
// approval tables. A distinct approver records their approval through the served
// POST /api/v1/identities/{id}/approvals endpoint (which requires certs:issue, the
// RA split). The store rejects a self-approval (approver == requester) and an
// anonymous approver. Tenant-scoped (AN-1).
type storeApprovalRecorder struct {
	store    *store.Store
	required int
}

// RecordApproval records approver's approval of action on resource and returns the
// resulting distinct-approver count. It ensures an approval request exists for the
// action (so an approval can be attributed even if the requester has not yet
// attempted the transition); the requester on an auto-opened request is empty, which
// imposes no self-approval constraint until the real requester attempts the gated
// transition (at which point the request already records them).
func (r storeApprovalRecorder) RecordApproval(ctx context.Context, tenantID, resource, action, approver string) (int, error) {
	required := r.required
	if required <= 0 {
		required = defaultRequiredApprovals
	}
	// Ensure a request row exists so the approval has a parent (FK). If the requester
	// already opened it (the common case once they attempt the transition), this is a
	// no-op that preserves their identity; otherwise it opens an unattributed request
	// that the requester's later gated attempt will not overwrite.
	if err := r.store.OpenIssuanceApprovalRequest(ctx, tenantID, resource, action, "", required); err != nil {
		return 0, err
	}
	return r.store.ApproveIssuance(ctx, tenantID, resource, action, approver)
}
