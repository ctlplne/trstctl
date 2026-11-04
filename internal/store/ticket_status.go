// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/ticketintake"
)

// Change-request approvals (P13): the requests intake opened from ServiceNow
// change requests and the relay reads of their approvals.

// IssuanceRequestsAwaitingTicket lists the requests intake opened from a
// ServiceNow table's tickets that still wait on a decision, oldest first.
func (s *Store) IssuanceRequestsAwaitingTicket(ctx context.Context, tenantID, table string, limit int) ([]IssuanceRequest, error) {
	out := []IssuanceRequest{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+issuanceRequestCols+` FROM issuance_requests
			WHERE tenant_id = $1 AND origin = $2 AND status = $3 AND starts_with(ticket_ref, $4)
			ORDER BY created_at, id LIMIT $5`,
			tenantID, ticketintake.SystemServiceNow, issuancerequest.StateRequested, table+":", limit)
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

// IssuanceRequestByTicket reads the one request a ticket opened.
func (s *Store) IssuanceRequestByTicket(ctx context.Context, tenantID, ticketRef string) (IssuanceRequest, bool, error) {
	var out IssuanceRequest
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanIssuanceRequest(tx.QueryRow(ctx, `SELECT `+issuanceRequestCols+` FROM issuance_requests
			WHERE tenant_id = $1 AND ticket_ref = $2`, tenantID, ticketRef))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return out, found, err
}

// HasPendingTicketStatusJob reports an unfinished status read for one intake
// schedule, so one read is in flight per schedule.
func (s *Store) HasPendingTicketStatusJob(ctx context.Context, tenantID, schedule string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM outbox WHERE tenant_id = $1 AND destination = 'ticket.status'
			   AND status IN ('pending', 'processing') AND claim_completed_at IS NULL
			   AND coalesce(nullif(convert_from(payload, 'UTF8')::jsonb ->> 'schedule', ''), 'default') = $2)`,
			tenantID, ticketintake.ScheduleName(schedule)).Scan(&pending)
	})
	return pending, err
}
