// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// IssuanceRequest is a first-class request for a credential (I3).
//
// Distinct from issuance_approval_requests, which is a dual-control GATE keyed
// on (tenant, resource, action) and can only answer "have enough people
// approved". This answers the requester's questions: was it denied, did it
// expire, can I withdraw it.
type IssuanceRequest struct {
	ID             string
	TenantID       string
	Subject        string
	Profile        string
	CSRPEM         string
	Requester      string
	Justification  string
	Origin         string
	TicketRef      string
	Status         string
	DecidedBy      string
	DecisionReason string
	DecidedAt      *time.Time
	IdentityID     string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

const issuanceRequestCols = `id::text, tenant_id::text, subject, profile, csr_pem, requester,
	justification, origin, ticket_ref, status, decided_by, decision_reason, decided_at,
	coalesce(identity_id::text, ''), expires_at, created_at`

func scanIssuanceRequest(row pgx.Row) (IssuanceRequest, error) {
	var r IssuanceRequest
	err := row.Scan(&r.ID, &r.TenantID, &r.Subject, &r.Profile, &r.CSRPEM, &r.Requester,
		&r.Justification, &r.Origin, &r.TicketRef, &r.Status, &r.DecidedBy, &r.DecisionReason,
		&r.DecidedAt, &r.IdentityID, &r.ExpiresAt, &r.CreatedAt)
	return r, err
}

// GetIssuanceRequest loads one request in its tenant context.
func (s *Store) GetIssuanceRequest(ctx context.Context, tenantID, id string) (IssuanceRequest, error) {
	var out IssuanceRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanIssuanceRequest(tx.QueryRow(ctx,
			`SELECT `+issuanceRequestCols+` FROM issuance_requests WHERE tenant_id = $1 AND id = $2`,
			tenantID, id))
		return err
	})
	return out, err
}

// ListIssuanceRequests returns the tenant's requests, newest first. A status
// filter of "" returns every state — an operator auditing what was DENIED needs
// the closed ones as much as the open queue needs the pending ones.
func (s *Store) ListIssuanceRequests(ctx context.Context, tenantID, status string, limit int) ([]IssuanceRequest, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []IssuanceRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+issuanceRequestCols+` FROM issuance_requests
			  WHERE tenant_id = $1 AND ($2 = '' OR status = $2)
			  ORDER BY created_at DESC LIMIT $3`, tenantID, status, limit)
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

// TenantsWithExpirableIssuanceRequests enumerates tenants holding a request that
// is still waiting and past due, so the leader-only sweep can visit each under
// its own RLS context.
func (s *Store) TenantsWithExpirableIssuanceRequests(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold an overdue issuance request so the leader-only expiry sweep can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM issuance_requests
		  WHERE status = 'requested' AND expires_at <= $1 ORDER BY tenant_id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DueIssuanceRequests returns the tenant's requests that have run out of time.
func (s *Store) DueIssuanceRequests(ctx context.Context, tenantID string, now time.Time, limit int) ([]IssuanceRequest, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []IssuanceRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+issuanceRequestCols+` FROM issuance_requests
			  WHERE tenant_id = $1 AND status = 'requested' AND expires_at <= $2
			  ORDER BY expires_at LIMIT $3`, tenantID, now, limit)
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

// ErrIssuanceRequestNotFound is returned when a decision names a request that
// does not exist in the caller's tenant.
var ErrIssuanceRequestNotFound = errors.New("store: issuance request not found")
