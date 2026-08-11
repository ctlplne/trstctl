// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"time"

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

// ErrIssuanceApprovalRequesterMismatch is returned when a caller tries to use an
// approval request under a different requester. The requester is part of the
// durable authorization fact; accepting a replacement would let a later actor
// inherit somebody else's approval.
var ErrIssuanceApprovalRequesterMismatch = errors.New("store: issuance approval requester does not match the durable request")

// ErrIssuanceApprovalRequirementMismatch is returned when a caller tries to lower
// or otherwise change the quorum bound into the durable request.
var ErrIssuanceApprovalRequirementMismatch = errors.New("store: issuance approval requirement does not match the durable request")

// ErrIssuanceApprovalNotLive is returned for expired, superseded, denied, legacy,
// or otherwise terminal approval state. Such a row is history, not authority.
var ErrIssuanceApprovalNotLive = errors.New("store: issuance approval request is not live")

// ErrIssuanceApprovalConsumed is returned when an operation tries to reuse an
// authority that already authorized one operation.
var ErrIssuanceApprovalConsumed = errors.New("store: issuance approval authority was already consumed")

// ErrIssuanceApprovalQuorumNotMet is returned when consumption is attempted before
// the request has its durably bound number of distinct, non-requester approvals.
var ErrIssuanceApprovalQuorumNotMet = errors.New("store: issuance approval quorum not met")

// defaultIssuanceApprovalTTL bounds the legacy request-opening signature, which
// predates an explicit expiry argument. Twenty-four hours gives humans a review
// window while ensuring an approval cannot silently become a standing permission.
const defaultIssuanceApprovalTTL = 24 * time.Hour

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
	Status    string
	ExpiresAt time.Time
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
	now := time.Now().UTC()
	var (
		boundRequester string
		boundRequired  int
		status         string
		unexpired      bool
	)
	err := tx.QueryRow(ctx,
		`INSERT INTO issuance_approval_requests
		        (tenant_id, resource, action, requester, required, created_at, expires_at, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
		 ON CONFLICT (tenant_id, resource, action) DO UPDATE
		    SET requester = CASE
		        WHEN issuance_approval_requests.requester = '' THEN EXCLUDED.requester
		        ELSE issuance_approval_requests.requester
		    END
		 RETURNING requester, required, coalesce(status, ''),
		           coalesce(expires_at > CURRENT_TIMESTAMP, false)`,
		tenantID, resource, action, requester, required, now, now.Add(defaultIssuanceApprovalTTL)).
		Scan(&boundRequester, &boundRequired, &status, &unexpired)
	if err != nil {
		return err
	}
	if requester != "" && boundRequester != requester {
		return ErrIssuanceApprovalRequesterMismatch
	}
	if boundRequired != required {
		return ErrIssuanceApprovalRequirementMismatch
	}
	if !isLiveIssuanceApprovalStatus(status) || !unexpired {
		return ErrIssuanceApprovalNotLive
	}
	return nil
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
		var (
			requester string
			required  int
			status    string
			unexpired bool
		)
		if err := tx.QueryRow(ctx,
			`SELECT requester, required, coalesce(status, ''),
			        coalesce(expires_at > CURRENT_TIMESTAMP, false)
			   FROM issuance_approval_requests
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3
			  FOR UPDATE`,
			tenantID, resource, action).Scan(&requester, &required, &status, &unexpired); err != nil {
			return err
		}
		// Separation of duties: the opener (requester) cannot also approve.
		if requester != "" && requester == approver {
			return ErrSelfIssuanceApproval
		}
		if status == "consumed" {
			return ErrIssuanceApprovalConsumed
		}
		if !isLiveIssuanceApprovalStatus(status) || !unexpired {
			return ErrIssuanceApprovalNotLive
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approvals (tenant_id, resource, action, approver)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, resource, action, approver) DO NOTHING`,
			tenantID, resource, action, approver); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM issuance_approvals
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3
			    AND approver <> $4`,
			tenantID, resource, action, requester).Scan(&count); err != nil {
			return err
		}
		if count >= required && status != "approved" {
			_, err := tx.Exec(ctx,
				`UPDATE issuance_approval_requests
				    SET status = 'approved'
				  WHERE tenant_id = $1 AND resource = $2 AND action = $3
				    AND status = 'pending'`,
				tenantID, resource, action)
			return err
		}
		return nil
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
			          WHERE ia.tenant_id = r.tenant_id AND ia.resource = r.resource AND ia.action = r.action
			            AND ia.approver <> r.requester),
			        coalesce(status, ''), coalesce(expires_at, created_at)
			   FROM issuance_approval_requests r
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
			tenantID, resource, action).
			Scan(&a.Requester, &a.Required, &a.Approvals, &a.Status, &a.ExpiresAt)
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
	var approved bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The request row, not the call arguments, owns the requester and quorum.
		// Equality checks make a stale caller fail closed; the count then excludes
		// that durably bound requester as a second self-approval defense.
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1
			     FROM issuance_approval_requests r
			    WHERE r.tenant_id = $1 AND r.resource = $2 AND r.action = $3
			      AND r.requester <> '' AND r.requester = $4 AND r.required = $5
			      AND r.status IN ('pending', 'approved')
			      AND r.expires_at > CURRENT_TIMESTAMP
			      AND (SELECT count(*)
			             FROM issuance_approvals ia
			            WHERE ia.tenant_id = r.tenant_id
			              AND ia.resource = r.resource
			              AND ia.action = r.action
			              AND ia.approver <> r.requester) >= r.required
			 )`,
			tenantID, resource, action, requester, required).Scan(&approved)
	})
	if err != nil {
		return false, err
	}
	return approved, nil
}

// ConsumeIssuanceApprovalTx atomically turns one live, quorum-backed approval into
// spent history. The caller supplies the transaction because the authorized state
// change must commit beside this consume marker; otherwise a crash could spend the
// approval without doing the work, or do the work while leaving approval reusable.
// Callers must already be inside Store.WithTenant for tenantID (AN-1).
func (s *Store) ConsumeIssuanceApprovalTx(ctx context.Context, tx pgx.Tx, tenantID, resource, action, requester string, required int) (IssuanceApproval, error) {
	if required <= 0 {
		required = 2
	}
	a := IssuanceApproval{
		TenantID: tenantID,
		Resource: resource,
		Action:   action,
	}
	var (
		expiresAt *time.Time
		unexpired bool
	)
	if err := tx.QueryRow(ctx,
		`SELECT requester, required, coalesce(status, ''), expires_at,
		        coalesce(expires_at > CURRENT_TIMESTAMP, false),
		        (SELECT count(*)
		           FROM issuance_approvals ia
		          WHERE ia.tenant_id = r.tenant_id
		            AND ia.resource = r.resource
		            AND ia.action = r.action
		            AND ia.approver <> r.requester)
		   FROM issuance_approval_requests r
		  WHERE tenant_id = $1 AND resource = $2 AND action = $3
		  FOR UPDATE`,
		tenantID, resource, action).
		Scan(&a.Requester, &a.Required, &a.Status, &expiresAt, &unexpired, &a.Approvals); err != nil {
		return IssuanceApproval{}, err
	}
	if expiresAt != nil {
		a.ExpiresAt = expiresAt.UTC()
	}
	if requester == "" || a.Requester != requester {
		return IssuanceApproval{}, ErrIssuanceApprovalRequesterMismatch
	}
	if a.Required != required {
		return IssuanceApproval{}, ErrIssuanceApprovalRequirementMismatch
	}
	if a.Status == "consumed" {
		return IssuanceApproval{}, ErrIssuanceApprovalConsumed
	}
	if !isLiveIssuanceApprovalStatus(a.Status) || !unexpired {
		return IssuanceApproval{}, ErrIssuanceApprovalNotLive
	}
	if a.Approvals < a.Required {
		return IssuanceApproval{}, ErrIssuanceApprovalQuorumNotMet
	}
	commandTag, err := tx.Exec(ctx,
		`UPDATE issuance_approval_requests
		    SET status = 'consumed'
		  WHERE tenant_id = $1 AND resource = $2 AND action = $3
		    AND status IN ('pending', 'approved')
		    AND expires_at > CURRENT_TIMESTAMP`,
		tenantID, resource, action)
	if err != nil {
		return IssuanceApproval{}, err
	}
	if commandTag.RowsAffected() != 1 {
		return IssuanceApproval{}, ErrIssuanceApprovalNotLive
	}
	a.Status = "consumed"
	return a, nil
}

func isLiveIssuanceApprovalStatus(status string) bool {
	return status == "pending" || status == "approved"
}
