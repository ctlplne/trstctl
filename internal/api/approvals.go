package api

import (
	"context"
	"net/http"

	"trstctl.com/trstctl/internal/authz"
)

// Served dual-control approval surface (EXC-WIRE-03). A distinct approver records an
// approval of a pending privileged action (an issue or a revoke) on an identity, so
// the served mutation gate can require two distinct approvers before the action
// proceeds (SEC-002, the served half of RED-004). Recording an approval requires the
// certs:issue authority — the RA split means a requester (certs:request) cannot
// approve, and the store additionally rejects a self-approval (requester == approver).
//
// The endpoint is idempotent (AN-5) like every mutation, tenant-scoped (AN-1), and
// records the approval through the event store (AN-2) under the authenticated
// principal. It is a no-op surface when no ApprovalRecorder is wired (the gate then
// has no dual-control backing and RequireApproval must be off).

// ApprovalRecorder records a distinct-approver approval of a privileged action on a
// resource and returns the resulting distinct-approver count. The served
// implementation is event-store backed and tenant-scoped (AN-1); it rejects a
// self-approval (the requester approving their own request). A nil recorder disables
// the served approval endpoint.
type ApprovalRecorder interface {
	// RecordApproval records that approver approves the given action on resource for
	// the tenant, returning the new distinct-approver count. It must reject a
	// self-approval and an anonymous approver.
	RecordApproval(ctx context.Context, tenantID, resource, action, approver string) (count int, err error)
}

// WithApprovals wires the served dual-control approval recorder that backs
// POST /api/v1/identities/{id}/approvals. When unset, that route reports the
// capability is unavailable.
func WithApprovals(r ApprovalRecorder) Option {
	return func(c *config) { c.approvals = r }
}

type approvalRequest struct {
	Action string `json:"action"` // "issue" | "revoke"
}

type approvalResponse struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Approver  string `json:"approver"`
	Approvals int    `json:"approvals"` // distinct-approver count after this approval
}

// approveIdentityAction records the caller's approval of a pending privileged action
// on an identity. The caller must hold certs:issue (enforced by the route guard);
// the recorder rejects a self-approval. The action ("issue"/"revoke") names which
// privileged transition is being approved.
//
//trstctl:mutation
func (a *API) approveIdentityAction(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.approvals == nil {
			return 0, nil, errStatus(http.StatusNotImplemented, "dual-control approval is not enabled on this deployment")
		}
		var req approvalRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		switch req.Action {
		case "issue", "revoke":
		default:
			return 0, nil, errStatus(http.StatusBadRequest, `action must be "issue" or "revoke"`)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated approver is required")
		}
		count, err := a.approvals.RecordApproval(ctx, tenantID, id, req.Action, principal.Subject)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, approvalResponse{Resource: id, Action: req.Action, Approver: principal.Subject, Approvals: count}, nil
	})
}
