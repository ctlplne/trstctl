// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Access graph reads (G1). The credential graph answers "who can reach this
// database?" from trstctl's own records: PAM sessions and the approvals they
// consumed, machine sessions, and issuance decisions. Every read is a tenant-scoped
// keyset page so a graph build over a large tenant never loads an unbounded
// result set in one query.

// PAMSessionAccess is the access-relevant slice of a PAM session: who asked for
// it, the workload it was attested to, the target and role it grants, and the
// approval its activation consumed.
type PAMSessionAccess struct {
	ID                string
	TargetType        string
	TargetID          string
	Role              string
	Status            string
	Subject           string
	RequestedBy       string
	ApprovalRequestID string
	StartedAt         time.Time
	ExpiresAt         time.Time
}

// ListLivePAMSessionAccessPage returns PAM sessions that may still grant access
// at now: active, revoking or with a failed revocation, and not yet expired. A
// session whose provider removal failed still counts, because its grant may
// still exist at the target.
func (s *Store) ListLivePAMSessionAccessPage(ctx context.Context, tenantID string, now time.Time, afterID string, limit int) ([]PAMSessionAccess, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("store: ListLivePAMSessionAccessPage requires a positive limit")
	}
	var out []PAMSessionAccess
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, target_type, target_id, role, status, subject, requested_by,
			        approval_request_id, started_at, expires_at
			   FROM pam_sessions
			  WHERE tenant_id = $1
			    AND id::text > $2
			    AND status IN ('active', 'revoking', 'revocation_failed')
			    AND expires_at > $3
			  ORDER BY id::text
			  LIMIT $4`,
			tenantID, afterID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p PAMSessionAccess
			if err := rows.Scan(&p.ID, &p.TargetType, &p.TargetID, &p.Role, &p.Status, &p.Subject, &p.RequestedBy,
				&p.ApprovalRequestID, &p.StartedAt, &p.ExpiresAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// OperationApprovalApprovers returns, for each named approval request, the
// principals who approved it, in the order they decided. Denials are not
// approvals and are left out.
func (s *Store) OperationApprovalApprovers(ctx context.Context, tenantID string, requestIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(requestIDs))
	if len(requestIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT request_id::text, approver
			   FROM operation_approval_decisions
			  WHERE tenant_id = $1
			    AND request_id::text = ANY($2::text[])
			    AND decision = 'approve'
			  ORDER BY request_id, decided_at, approver`,
			tenantID, requestIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var requestID, approver string
			if err := rows.Scan(&requestID, &approver); err != nil {
				return err
			}
			out[requestID] = append(out[requestID], approver)
		}
		return rows.Err()
	})
	return out, err
}

// ListMachineSessionsAfter pages every machine session of the tenant in id
// order. The newest-first ListMachineSessions is capped for display; a graph
// build must see all of them.
func (s *Store) ListMachineSessionsAfter(ctx context.Context, tenantID, afterID string, limit int) ([]MachineSession, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("store: ListMachineSessionsAfter requires a positive limit")
	}
	var out []MachineSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id, principal, method, scopes, status, issued_at, expires_at, revoked_at, revoked_by
			   FROM machine_sessions
			  WHERE tenant_id = $1
			    AND id > $2
			  ORDER BY id
			  LIMIT $3`,
			tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m MachineSession
			if err := scanMachineSession(rows, &m); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// ListIssuanceRequestsAfter pages the tenant's issuance requests in a given
// status in id order, for readers that need all of them rather than the capped
// newest-first queue.
func (s *Store) ListIssuanceRequestsAfter(ctx context.Context, tenantID, status, afterID string, limit int) ([]IssuanceRequest, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("store: ListIssuanceRequestsAfter requires a positive limit")
	}
	var out []IssuanceRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+issuanceRequestCols+` FROM issuance_requests
			  WHERE tenant_id = $1 AND ($2 = '' OR status = $2) AND id::text > $3
			  ORDER BY id::text LIMIT $4`, tenantID, status, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanIssuanceRequest(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
