// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrPAMAccountFlagNotFound is an account with no flag.
var ErrPAMAccountFlagNotFound = errors.New("store: brokered account flag not found")

// PAMAccountFlag is a brokered account's latest flag (A276): why it was
// flagged, and what an approved action did about it.
type PAMAccountFlag struct {
	TargetType, TargetID                                                                 string
	Reasons                                                                              []string
	Detail, OwnerID                                                                      string
	LastUsedAt                                                                           *time.Time
	FlaggedAt                                                                            time.Time
	Status                                                                               string // open, cleared, actioned
	ClearedAt                                                                            *time.Time
	Action, ActionOwnerID, ActionRotationID, ActionReason, ApprovalRequestID, ActionedBy string
	ActionedAt                                                                           *time.Time
}

const pamAccountFlagColumns = `target_type, target_id, reasons, detail, owner_id, last_used_at, flagged_at, status, cleared_at,
 action, action_owner_id, action_rotation_id, action_reason, approval_request_id, actioned_by, actioned_at`

func scanPAMAccountFlag(row pgx.Row) (PAMAccountFlag, error) {
	var f PAMAccountFlag
	err := row.Scan(&f.TargetType, &f.TargetID, &f.Reasons, &f.Detail, &f.OwnerID, &f.LastUsedAt, &f.FlaggedAt, &f.Status, &f.ClearedAt,
		&f.Action, &f.ActionOwnerID, &f.ActionRotationID, &f.ActionReason, &f.ApprovalRequestID, &f.ActionedBy, &f.ActionedAt)
	return f, err
}

// ApplyPAMAccountFlaggedTx projects pam.account.flagged: the account's flag
// opens (again) with its reasons.
func (s *Store) ApplyPAMAccountFlaggedTx(ctx context.Context, tx pgx.Tx, tenantID string, f PAMAccountFlag) error {
	_, err := tx.Exec(ctx, `INSERT INTO pam_account_flags (tenant_id, target_type, target_id, reasons, detail, owner_id, last_used_at, flagged_at, status)
	 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, 'open')
	 ON CONFLICT (tenant_id, target_type, target_id) DO UPDATE SET reasons = EXCLUDED.reasons, detail = EXCLUDED.detail,
	   owner_id = EXCLUDED.owner_id, last_used_at = EXCLUDED.last_used_at, flagged_at = EXCLUDED.flagged_at, status = 'open',
	   cleared_at = NULL, action = '', action_owner_id = '', action_rotation_id = '', action_reason = '', approval_request_id = '',
	   actioned_by = '', actioned_at = NULL`,
		tenantID, f.TargetType, f.TargetID, f.Reasons, f.Detail, f.OwnerID, f.LastUsedAt, f.FlaggedAt.UTC())
	return err
}

// ApplyPAMAccountFlagClearedTx projects pam.account.flag_cleared: what the
// flag named no longer holds.
func (s *Store) ApplyPAMAccountFlagClearedTx(ctx context.Context, tx pgx.Tx, tenantID, targetType, targetID string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_account_flags SET status = 'cleared', cleared_at = $4
	 WHERE tenant_id = $1::uuid AND target_type = $2 AND target_id = $3 AND status = 'open'`, tenantID, targetType, targetID, at.UTC())
	return err
}

// ApplyPAMAccountFlagActionedTx projects pam.account.flag_actioned: the
// approved action applied to an open flag.
func (s *Store) ApplyPAMAccountFlagActionedTx(ctx context.Context, tx pgx.Tx, tenantID string, f PAMAccountFlag) error {
	tag, err := tx.Exec(ctx, `UPDATE pam_account_flags SET status = 'actioned', action = $4, action_owner_id = $5, action_rotation_id = $6,
	   action_reason = $7, approval_request_id = $8, actioned_by = $9, actioned_at = $10
	 WHERE tenant_id = $1::uuid AND target_type = $2 AND target_id = $3 AND (status = 'open' OR approval_request_id = $8)`,
		tenantID, f.TargetType, f.TargetID, f.Action, f.ActionOwnerID, f.ActionRotationID, f.ActionReason, f.ApprovalRequestID, f.ActionedBy, f.ActionedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPAMAccountFlagNotFound
	}
	return nil
}

// GetPAMAccountFlag is one account's flag.
func (s *Store) GetPAMAccountFlag(ctx context.Context, tenantID, targetType, targetID string) (PAMAccountFlag, error) {
	var out PAMAccountFlag
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanPAMAccountFlag(tx.QueryRow(ctx, `SELECT `+pamAccountFlagColumns+` FROM pam_account_flags
		 WHERE tenant_id = $1::uuid AND target_type = $2 AND target_id = $3`, tenantID, targetType, targetID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMAccountFlag{}, ErrPAMAccountFlagNotFound
	}
	return out, err
}

// ListPAMAccountFlags lists a tenant's flags, newest first; only one status
// when it is named.
func (s *Store) ListPAMAccountFlags(ctx context.Context, tenantID, status string) ([]PAMAccountFlag, error) {
	var out []PAMAccountFlag
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamAccountFlagColumns+` FROM pam_account_flags
		 WHERE tenant_id = $1::uuid AND ($2 = '' OR status = $2) ORDER BY flagged_at DESC, target_type, target_id LIMIT 1000`, tenantID, status)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanPAMAccountFlag(rows)
			if err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// PAMAccountLastUses is when each of a tenant's brokered accounts was last
// used: its newest session or revealed check-out.
func (s *Store) PAMAccountLastUses(ctx context.Context, tenantID string) (map[[2]string]time.Time, error) {
	out := map[[2]string]time.Time{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT target_type, target_id, max(at) FROM (
		   SELECT target_type, target_id, started_at AS at FROM pam_sessions WHERE tenant_id = $1::uuid
		   UNION ALL
		   SELECT target_type, target_id, revealed_at AS at FROM pam_checkouts WHERE tenant_id = $1::uuid
		 ) uses GROUP BY target_type, target_id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var targetType, targetID string
			var at time.Time
			if err := rows.Scan(&targetType, &targetID, &at); err != nil {
				return err
			}
			out[[2]string{targetType, targetID}] = at
		}
		return rows.Err()
	})
	return out, err
}

// ListTenantsWithPAMTargets lists the tenants that registered brokered
// accounts, for the flag scan.
func (s *Store) ListTenantsWithPAMTargets(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant system worker: the brokered account flag scan finds which tenants registered targets; it reads tenant_id only, and each tenant's accounts are read and flagged under the owning tenant's RLS context.
		`SELECT DISTINCT tenant_id::text FROM pam_targets LIMIT $1`, limit)
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
