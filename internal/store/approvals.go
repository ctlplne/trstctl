// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Served dual-control for privileged issuance/revoke (EXC-WIRE-03; closes SEC-002,
// the served half of RED-004). These repositories back the served mutation gate's
// distinct-approver requirement. They mirror the proven m-of-n CA key-ceremony
// approval store (CreateKeyCeremony plus evidence-backed approval reservation):
// every query is tenant-scoped and runs under row-level security (AN-1), an
// approver's approval is idempotent, and the request opener (requester) may NOT
// approve their own request (opener != approver separation of duties — the
// dual-control invariant).

// ErrSelfIssuanceApproval is returned when the requester of a privileged action
// attempts to approve it themselves. Dual control requires a DISTINCT approver
// (SEC-002, RED-004), so a self-approval is refused and never recorded.
var ErrSelfIssuanceApproval = errors.New("store: the requester may not approve their own issuance/revocation (dual control requires a distinct approver)")

// ErrAnonymousIssuanceApproval is returned when an approval carries no approver
// identity. An approval must be attributable to an authenticated principal.
var ErrAnonymousIssuanceApproval = errors.New("store: issuance approval requires an authenticated approver identity")

// IssuanceApproval is the state of a pending privileged action's dual-control
// approval: the requester who opened it, the number of required distinct approvals,
// and the current distinct-approver count.
type IssuanceApproval struct {
	TenantID  string
	Resource  string
	Action    string
	Requester string
	Required  int
	Approvals int
}

// OpenIssuanceApprovalRequest records (idempotently) that a privileged action on a
// resource awaits dual-control approval, capturing the requester for the opener !=
// approver check. It is tenant-scoped under RLS (AN-1).
//
// Requester semantics (the self-approval defense): a NON-EMPTY requester is bound to
// the request — on conflict it is set if the row had none, OR kept if it already
// names someone (the FIRST non-empty requester wins, so a later caller cannot
// overwrite the requester to launder a self-approval). An EMPTY requester (used when
// an approver records an approval before the requester has attempted the gated
// transition) never clears an existing requester. This means: whoever actually
// drives the gated transition is recorded as the requester, and the store will
// refuse to count their own approval.
func (s *Store) OpenIssuanceApprovalRequest(ctx context.Context, tenantID, resource, action, requester string, required int) error {
	if required <= 0 {
		required = 2 // dual control
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.OpenIssuanceApprovalRequestTx(ctx, tx, tenantID, resource, action, requester, required)
	})
}

// OpenIssuanceApprovalRequestTx is the transaction-aware form used by producers
// that must commit another durable fact beside the request. In particular, the
// served mutation gate calls it immediately before enqueueing the approval
// notification on the same tx (AN-6). Callers must already be inside
// Store.WithTenant for tenantID; every predicate still carries tenant_id so RLS
// remains a second isolation boundary (AN-1).
func (s *Store) OpenIssuanceApprovalRequestTx(ctx context.Context, tx pgx.Tx, tenantID, resource, action, requester string, required int) error {
	if required <= 0 {
		required = 2
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester, required)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (tenant_id, resource, action) DO UPDATE
		    SET requester = CASE
		        WHEN issuance_approval_requests.requester = '' THEN EXCLUDED.requester
		        ELSE issuance_approval_requests.requester
		    END`,
		tenantID, resource, action, requester, required)
	return err
}

// ApproveIssuance records a distinct approver's approval of a privileged action and
// returns the resulting distinct-approval count. It enforces dual control in the
// same tenant-scoped transaction as the insert, fail-closed:
//   - the approver must be a named identity (not empty);
//   - the request's requester may NOT approve their own request (self-approval);
//
// so a disallowed approval is never recorded. An approval request must already exist
// (opened by OpenIssuanceApprovalRequest); approving an unknown request is an error.
func (s *Store) ApproveIssuance(ctx context.Context, tenantID, resource, action, approver string) (int, error) {
	if approver == "" {
		return 0, ErrAnonymousIssuanceApproval
	}
	var count int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var requester string
		if err := tx.QueryRow(ctx,
			`SELECT requester FROM issuance_approval_requests
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
			tenantID, resource, action).Scan(&requester); err != nil {
			return err
		}
		// Separation of duties: the opener (requester) cannot also approve.
		if requester != "" && requester == approver {
			return ErrSelfIssuanceApproval
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approvals (tenant_id, resource, action, approver)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, resource, action, approver) DO NOTHING`,
			tenantID, resource, action, approver); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM issuance_approvals
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
			tenantID, resource, action).Scan(&count)
	})
	return count, err
}

// GetIssuanceApproval loads the dual-control state for a privileged action: the
// requester, the required count, and the current DISTINCT-approver count. A missing
// request yields a not-found error. It is tenant-scoped under RLS (AN-1).
func (s *Store) GetIssuanceApproval(ctx context.Context, tenantID, resource, action string) (IssuanceApproval, error) {
	a := IssuanceApproval{TenantID: tenantID, Resource: resource, Action: action}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT requester, required,
			        (SELECT count(*) FROM issuance_approvals ia
			          WHERE ia.tenant_id = r.tenant_id AND ia.resource = r.resource AND ia.action = r.action)
			   FROM issuance_approval_requests r
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
			tenantID, resource, action).Scan(&a.Requester, &a.Required, &a.Approvals)
	})
	return a, err
}

// HasDistinctApproval reports whether a privileged action has at least `required`
// DISTINCT-approver approvals on record, NONE of which is the requester. It is the
// predicate the served mutation gate consults: it returns false (deny) for an
// unknown request, an insufficient count, or — defensively — a count that would only
// be reached by counting the requester's own approval (the store already refuses to
// record that, so this is belt-and-suspenders). Tenant-scoped under RLS (AN-1).
func (s *Store) HasDistinctApproval(ctx context.Context, tenantID, resource, action, requester string, required int) (bool, error) {
	if required <= 0 {
		required = 2
	}
	var count int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Count approvals by principals OTHER than the requester, so even if a stale
		// self-approval row existed it could not satisfy the threshold.
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM issuance_approvals
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3 AND approver <> $4`,
			tenantID, resource, action, requester).Scan(&count)
	})
	if err != nil {
		return false, err
	}
	return count >= required, nil
}
