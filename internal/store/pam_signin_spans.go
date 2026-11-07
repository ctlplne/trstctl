// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// A274: bypass detection explains a managed account's sign-ins by the spans
// in which trstctl itself, or a person it let in, signed in as the account.
// These reads list the sessions, check-outs and rotation commands that
// overlap a collection's span.

// ListPAMSessionsOverlapping lists a tenant's sessions that started by to and
// had not ended before from (their end: when they ended, else their
// deadline), oldest first.
func (s *Store) ListPAMSessionsOverlapping(ctx context.Context, tenantID string, from, to time.Time, limit int) ([]PAMSession, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	var out []PAMSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id::text, target_type, target_id, role, status,
			        subject, requested_by, reason, attestation_id, backend_ref, ssh_key_id,
			        ssh_serial, idempotency_key, audit, attestation, started_at, expires_at, ended_at,
			        revocation_requested_by, revocation_reason, revocation_requested_at,
			        revocation_idempotency_key, revocation_failure, revocation_failed_at,
			        delivery, COALESCE(gateway_agent_id::text, ''), gateway_ticket_digest, ssh_principal,
			        gateway_ended_at, gateway_ended, command_policy, COALESCE(approval_request_id::text, ''), web_sign_in
			   FROM pam_sessions
			  WHERE tenant_id = $1 AND started_at <= $3 AND COALESCE(ended_at, expires_at) >= $2
			  ORDER BY started_at, id
			  LIMIT $4`,
			tenantID, from.UTC(), to.UTC(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p PAMSession
			if err := scanPAMSession(rows, &p); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// ListPAMCheckoutsOverlapping lists a provider's check-outs revealed by to
// and not ended before from, oldest first.
func (s *Store) ListPAMCheckoutsOverlapping(ctx context.Context, tenantID, providerID string, from, to time.Time, limit int) ([]PAMCheckout, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	var out []PAMCheckout
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamCheckoutColumns+` FROM pam_checkouts
			  WHERE tenant_id = $1::uuid AND provider_id = $2 AND revealed_at <= $4 AND COALESCE(ended_at, expires_at) >= $3
			  ORDER BY revealed_at, request_id LIMIT $5`, tenantID, providerID, from.UTC(), to.UTC(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanPAMCheckout(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// PAMRotationSpan is when a static rotation of a provider's secret ran: the
// rotation proves the new credential (and may restore the old) by signing in.
type PAMRotationSpan struct {
	ID, Key            string
	CreatedAt, EndedAt time.Time
}

// ListStaticRotationSpansOverlapping lists a provider's static rotation
// commands that ran during [from, to] (their end: when they became terminal,
// else their last update).
func (s *Store) ListStaticRotationSpansOverlapping(ctx context.Context, tenantID, provider string, from, to time.Time, limit int) ([]PAMRotationSpan, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	var out []PAMRotationSpan
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, secret_key, created_at, COALESCE(terminal_at, updated_at)
			   FROM secret_static_rotation_commands
			  WHERE tenant_id = $1::uuid AND provider = $2 AND created_at <= $4 AND COALESCE(terminal_at, updated_at) >= $3
			  ORDER BY created_at, id LIMIT $5`, tenantID, provider, from.UTC(), to.UTC(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r PAMRotationSpan
			if err := rows.Scan(&r.ID, &r.Key, &r.CreatedAt, &r.EndedAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
