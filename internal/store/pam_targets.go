// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrPAMTargetNotFound = errors.New("store: PAM target not found")

type PAMTarget struct {
	TenantID, TargetType, ID, ProviderID string
	AllowedRoles                         []string
	Host                                 string
	Port                                 int
	Principals                           []string
	Enabled                              bool
	RegisteredBy                         string
	RegisteredAt                         time.Time
	DisabledBy, DisabledReason           string
	DisabledAt                           *time.Time
}

const pamTargetColumns = `tenant_id::text, target_type, id, provider_id, allowed_roles,
    host, port, principals, enabled, registered_by, registered_at,
    disabled_by, disabled_reason, disabled_at`

func scanPAMTarget(row pgx.Row) (PAMTarget, error) {
	var rec PAMTarget
	err := row.Scan(&rec.TenantID, &rec.TargetType, &rec.ID, &rec.ProviderID,
		&rec.AllowedRoles, &rec.Host, &rec.Port, &rec.Principals, &rec.Enabled,
		&rec.RegisteredBy, &rec.RegisteredAt, &rec.DisabledBy, &rec.DisabledReason, &rec.DisabledAt)
	return rec, err
}

func (s *Store) ApplyPAMTargetRegisteredTx(ctx context.Context, tx pgx.Tx, rec PAMTarget) error {
	_, err := tx.Exec(ctx, `INSERT INTO pam_targets
        (tenant_id, target_type, id, provider_id, allowed_roles, host, port,
         principals, enabled, registered_by, registered_at)
		 VALUES ($1::uuid,$2,$3,$4,COALESCE($5::text[], '{}'::text[]),$6,$7,
		         COALESCE($8::text[], '{}'::text[]),true,$9,$10)
        ON CONFLICT (tenant_id,target_type,id) DO NOTHING`,
		rec.TenantID, rec.TargetType, rec.ID, rec.ProviderID, rec.AllowedRoles,
		rec.Host, rec.Port, rec.Principals, rec.RegisteredBy, rec.RegisteredAt)
	return err
}

func (s *Store) ApplyPAMTargetDisabledTx(ctx context.Context, tx pgx.Tx, tenantID, targetType, id, actor, reason string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_targets SET enabled=false, disabled_by=$4,
        disabled_reason=$5, disabled_at=$6 WHERE tenant_id=$1::uuid AND target_type=$2 AND id=$3 AND enabled=true`,
		tenantID, targetType, id, actor, reason, at)
	return err
}

func (s *Store) GetPAMTarget(ctx context.Context, tenantID, targetType, id string) (PAMTarget, error) {
	var rec PAMTarget
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var scanErr error
		rec, scanErr = scanPAMTarget(tx.QueryRow(ctx,
			`SELECT `+pamTargetColumns+` FROM pam_targets WHERE tenant_id=$1::uuid AND target_type=$2 AND id=$3`,
			tenantID, targetType, id))
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMTarget{}, ErrPAMTargetNotFound
	}
	return rec, err
}

func (s *Store) ListPAMTargets(ctx context.Context, tenantID string) ([]PAMTarget, error) {
	var out []PAMTarget
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamTargetColumns+` FROM pam_targets WHERE tenant_id=$1::uuid ORDER BY target_type,id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			rec, err := scanPAMTarget(rows)
			if err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}
