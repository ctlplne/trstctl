// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// CA calendar repository (H5). These are the reads and the one write behind
// year-scale CA expiry alerting. Every tenant-facing query runs under RLS (AN-1);
// the single cross-tenant call is the leader's enumerator and is marked as such.
//
// The horizon band itself is computed at read time from not_after (see
// internal/lifecycle/cahorizon.go) and is deliberately not stored: a band is a
// judgment about a moment, and baking it into a row would make it stale the day
// after it was written. What IS stored is which band an authority has already
// been alerted at, so the scheduler re-alerts on each tightening instead of
// repeating itself every sweep.

// CAHorizonCandidate is a CA authority the horizon sweep evaluates, carrying only
// what the decision needs: the expiry, and the tightest band already notified.
type CAHorizonCandidate struct {
	ID               string
	CommonName       string
	Kind             string
	NotAfter         time.Time
	AlertedMonths    *int
	HorizonAlertedAt *time.Time
	ActiveLeafCount  int
}

// TenantsWithCAHorizonCandidates returns tenant ids that operate at least one
// active CA authority with a known expiry. It is a system enumerator only: the
// leader uses it to decide which tenants to sweep, then re-enters tenant-scoped
// RLS for the authority rows themselves.
func (s *Store) TenantsWithCAHorizonCandidates(ctx context.Context) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: the leader scheduler enumerates which tenants operate CA authorities with a known expiry, then re-enters tenant-scoped RLS for the rows themselves.
		`SELECT DISTINCT tenant_id::text
		   FROM ca_authorities
		  WHERE status = 'active'
		    AND not_after IS NOT NULL
		  ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	return tenants, rows.Err()
}

// ListCAHorizonCandidates returns a tenant's active CA authorities that carry an
// expiry, soonest first. The sweep evaluates every one of them rather than
// pre-filtering in SQL: the band thresholds are policy, and keeping policy in one
// place (internal/lifecycle) beats splitting it across a WHERE clause.
func (s *Store) ListCAHorizonCandidates(ctx context.Context, tenantID string) ([]CAHorizonCandidate, error) {
	var out []CAHorizonCandidate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, common_name, kind, not_after, horizon_alerted_months, horizon_alerted_at
			   FROM ca_authorities
			  WHERE tenant_id = $1
			    AND status = 'active'
			    AND not_after IS NOT NULL
			  ORDER BY not_after, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CAHorizonCandidate
			if err := rows.Scan(&c.ID, &c.CommonName, &c.Kind, &c.NotAfter, &c.AlertedMonths, &c.HorizonAlertedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// MarkCAAuthorityHorizonAlertedTx projects an immutable horizon decision in the
// caller's transaction. A replay of an older band must leave both the tightest
// band and its timestamp unchanged.
func (s *Store) MarkCAAuthorityHorizonAlertedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, band int, at time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE ca_authorities
		    SET horizon_alerted_at = CASE
		            WHEN horizon_alerted_months IS NULL OR horizon_alerted_months > $3 THEN $4
		            ELSE horizon_alerted_at END,
		        horizon_alerted_months = LEAST(COALESCE(horizon_alerted_months, $3), $3)
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, band, at.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

// CountActiveLeavesForAuthority reports how many active certificates were issued
// under an authority, so an alert can say how much of the estate is behind the
// expiring anchor instead of naming a CA in isolation.
func (s *Store) CountActiveLeavesForAuthority(ctx context.Context, tenantID, authorityID string) (int, error) {
	var count int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*)
			   FROM ca_issued_certs
			  WHERE tenant_id = $1 AND ca_id = $2 AND revoked_at IS NULL`, tenantID, authorityID).Scan(&count)
	})
	return count, err
}
