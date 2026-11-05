// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// PAMAccountHealth is a brokered account's credential health (A258): the
// outcome class of the last sign-in check of the credential its target's
// provider holds, and when the account began failing.
type PAMAccountHealth struct {
	TargetType, TargetID, ProviderID string
	Status                           string
	Attempts                         int
	CheckedAt                        time.Time
	FailingSince                     *time.Time
}

// ApplyPAMAccountHealthCheckedTx projects pam.account.health_checked. A check
// older than the one recorded changes nothing; failing_since is set by the
// first failing check after a healthy one (or the first check) and cleared by
// a healthy one.
func (s *Store) ApplyPAMAccountHealthCheckedTx(ctx context.Context, tx pgx.Tx, tenantID string, h PAMAccountHealth) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO pam_account_health AS cur (tenant_id, target_type, target_id, provider_id, status, attempts, checked_at, failing_since)
		VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $5 = 'healthy' THEN NULL ELSE $7::timestamptz END)
		ON CONFLICT (tenant_id, target_type, target_id) DO UPDATE SET
		    provider_id = EXCLUDED.provider_id, status = EXCLUDED.status, attempts = EXCLUDED.attempts,
		    checked_at = EXCLUDED.checked_at,
		    failing_since = CASE WHEN EXCLUDED.status = 'healthy' THEN NULL
		                         WHEN cur.status = 'healthy' OR cur.failing_since IS NULL THEN EXCLUDED.checked_at
		                         ELSE cur.failing_since END
		  WHERE cur.checked_at <= EXCLUDED.checked_at`,
		tenantID, h.TargetType, h.TargetID, h.ProviderID, h.Status, h.Attempts, h.CheckedAt.UTC())
	return err
}

// ListPAMAccountHealth returns a tenant's brokered accounts' health, keyed by
// target type and ID.
func (s *Store) ListPAMAccountHealth(ctx context.Context, tenantID string) (map[[2]string]PAMAccountHealth, error) {
	out := map[[2]string]PAMAccountHealth{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT target_type, target_id, provider_id, status, attempts, checked_at, failing_since
			FROM pam_account_health WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h PAMAccountHealth
			if err := rows.Scan(&h.TargetType, &h.TargetID, &h.ProviderID, &h.Status, &h.Attempts, &h.CheckedAt, &h.FailingSince); err != nil {
				return err
			}
			out[[2]string{h.TargetType, h.TargetID}] = h
		}
		return rows.Err()
	})
	return out, err
}

// ListEnabledProviderPAMTargets lists every tenant's enabled registered
// targets that name a provider, for the credential health worker (A258).
func (s *Store) ListEnabledProviderPAMTargets(ctx context.Context) ([]PAMTarget, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — the PAM credential health worker checks every tenant's provider-backed targets, as the expiry worker scans every tenant's sessions; each check is then recorded under its own tenant's RLS context.
		`SELECT `+pamTargetColumns+` FROM pam_targets WHERE enabled AND provider_id <> '' ORDER BY tenant_id, target_type, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMTarget
	for rows.Next() {
		rec, err := scanPAMTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
