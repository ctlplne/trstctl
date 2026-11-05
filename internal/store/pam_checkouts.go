// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrPAMCheckoutNotFound is a check-out that does not exist.
var ErrPAMCheckoutNotFound = errors.New("store: PAM check-out not found")

// PAMCheckout is a vaulted account's check-out (A261 part 2): revealed once to
// its requester, ended by check-in or its deadline with the rotation that
// retires the revealed credential. It never holds the credential.
type PAMCheckout struct {
	// TenantID is set only by the expiry worker's cross-tenant list.
	TenantID                   string
	RequestID                  string
	TargetType, TargetID       string
	ProviderID                 string
	AccountSecret              string
	SecretVersion              int
	RequestedBy, Reason        string
	ApprovalRequestID          string
	RevealedAt, ExpiresAt      time.Time
	Status                     string
	EndedAt                    *time.Time
	EndedBy, RotationCommandID string
}

const pamCheckoutColumns = `request_id::text, target_type, target_id, provider_id, account_secret, secret_version, requested_by, reason,
    approval_request_id::text, revealed_at, expires_at, status, ended_at, ended_by, rotation_command_id`

func scanPAMCheckout(row pgx.Row) (PAMCheckout, error) {
	var c PAMCheckout
	err := row.Scan(&c.RequestID, &c.TargetType, &c.TargetID, &c.ProviderID, &c.AccountSecret, &c.SecretVersion, &c.RequestedBy, &c.Reason,
		&c.ApprovalRequestID, &c.RevealedAt, &c.ExpiresAt, &c.Status, &c.EndedAt, &c.EndedBy, &c.RotationCommandID)
	return c, err
}

// ApplyPAMCheckoutRevealedTx projects pam.checkout.revealed. Replaying it
// changes nothing.
func (s *Store) ApplyPAMCheckoutRevealedTx(ctx context.Context, tx pgx.Tx, tenantID string, c PAMCheckout) error {
	_, err := tx.Exec(ctx, `INSERT INTO pam_checkouts (tenant_id, request_id, target_type, target_id, provider_id, account_secret, secret_version,
	        requested_by, reason, approval_request_id, revealed_at, expires_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'revealed') ON CONFLICT (tenant_id, request_id) DO NOTHING`,
		tenantID, c.RequestID, c.TargetType, c.TargetID, c.ProviderID, c.AccountSecret, c.SecretVersion, c.RequestedBy, c.Reason, c.ApprovalRequestID,
		c.RevealedAt.UTC(), c.ExpiresAt.UTC())
	return err
}

// ApplyPAMCheckoutEndedTx projects pam.checkout.ended: checked in or expired,
// with the rotation queued to retire the revealed credential.
func (s *Store) ApplyPAMCheckoutEndedTx(ctx context.Context, tx pgx.Tx, tenantID, requestID, status, actor, rotationCommandID string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_checkouts SET status = $3, ended_at = $4, ended_by = $5, rotation_command_id = $6
		WHERE tenant_id = $1 AND request_id = $2 AND status = 'revealed'`, tenantID, requestID, status, at.UTC(), actor, rotationCommandID)
	return err
}

// GetPAMCheckout returns a check-out.
func (s *Store) GetPAMCheckout(ctx context.Context, tenantID, requestID string) (PAMCheckout, error) {
	var c PAMCheckout
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		c, err = scanPAMCheckout(tx.QueryRow(ctx, `SELECT `+pamCheckoutColumns+` FROM pam_checkouts WHERE tenant_id = $1 AND request_id = $2`,
			tenantID, requestID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMCheckout{}, ErrPAMCheckoutNotFound
	}
	c.TenantID = tenantID
	return c, err
}

// ListPAMCheckouts lists the tenant's check-outs, newest first.
func (s *Store) ListPAMCheckouts(ctx context.Context, tenantID string, limit int) ([]PAMCheckout, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	var out []PAMCheckout
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamCheckoutColumns+` FROM pam_checkouts WHERE tenant_id = $1
			ORDER BY revealed_at DESC, request_id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanPAMCheckout(rows)
			if err != nil {
				return err
			}
			c.TenantID = tenantID
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ListDuePAMCheckouts lists every tenant's revealed check-outs past their
// deadline, for the expiry worker.
func (s *Store) ListDuePAMCheckouts(ctx context.Context, now time.Time, limit int) ([]PAMCheckout, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — a cross-tenant read by design: the check-out expiry worker finds every tenant's revealed check-outs past their deadline (tenant_id, request and target; no credential), and each rotation and its event then run under that check-out's own tenant's RLS context.
		`SELECT tenant_id::text, `+pamCheckoutColumns+` FROM pam_checkouts WHERE status = 'revealed' AND expires_at <= $1
		  ORDER BY expires_at, tenant_id, request_id LIMIT $2`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMCheckout
	for rows.Next() {
		var c PAMCheckout
		if err := rows.Scan(&c.TenantID, &c.RequestID, &c.TargetType, &c.TargetID, &c.ProviderID, &c.AccountSecret, &c.SecretVersion, &c.RequestedBy,
			&c.Reason, &c.ApprovalRequestID, &c.RevealedAt, &c.ExpiresAt, &c.Status, &c.EndedAt, &c.EndedBy, &c.RotationCommandID); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
