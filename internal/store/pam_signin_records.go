// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// PAMSignInRecord is one sign-in bypass detection read (A274).
type PAMSignInRecord struct {
	ProviderID, Fingerprint, Account string
	At                               time.Time
	Earliest                         *time.Time
	Source, Method, KeyID, Ref       string
	ExplainedBy, ExplainedRef        string
	Collector, RunID                 string
	SeenAt                           time.Time
}

// ApplyPAMSignInsCollectedTx projects pam.signin.collected: each sign-in is
// one row per provider and fingerprint. It keeps the verdict of the run that
// first read it — the one its finding, if any, came from — so a window that
// began later never re-explains it; a later run only refreshes when it was
// last seen.
func (s *Store) ApplyPAMSignInsCollectedTx(ctx context.Context, tx pgx.Tx, tenantID string, records []PAMSignInRecord) error {
	for _, r := range records {
		if _, err := tx.Exec(ctx, `INSERT INTO pam_signin_records
		        (tenant_id, provider_id, fingerprint, account, signed_in_at, earliest_at, source, method, key_id, ref,
		         explained_by, explained_ref, collector, first_run_id, last_seen_at)
		 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (tenant_id, provider_id, fingerprint) DO UPDATE SET
		        last_seen_at = GREATEST(pam_signin_records.last_seen_at, EXCLUDED.last_seen_at)`,
			tenantID, r.ProviderID, r.Fingerprint, r.Account, r.At.UTC(), r.Earliest, r.Source, r.Method, r.KeyID, r.Ref,
			r.ExplainedBy, r.ExplainedRef, r.Collector, r.RunID, r.SeenAt.UTC()); err != nil {
			return err
		}
	}
	return nil
}

// ApplyPAMSignInsPurgedTx projects pam.signin.records_purged: the tenant's
// sign-ins from before the retention horizon go.
func (s *Store) ApplyPAMSignInsPurgedTx(ctx context.Context, tx pgx.Tx, tenantID string, before time.Time) error {
	_, err := tx.Exec(ctx, `DELETE FROM pam_signin_records WHERE tenant_id = $1::uuid AND signed_in_at < $2`, tenantID, before.UTC())
	return err
}

// ListPAMSignInRecords lists a tenant's recorded sign-ins, newest first:
// one provider's when providerID is set, only the unexplained when asked.
func (s *Store) ListPAMSignInRecords(ctx context.Context, tenantID, providerID string, unexplainedOnly bool, limit int) ([]PAMSignInRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	var out []PAMSignInRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT provider_id, fingerprint, account, signed_in_at, earliest_at, source, method, key_id, ref,
		        explained_by, explained_ref, collector, first_run_id, last_seen_at
		   FROM pam_signin_records
		  WHERE tenant_id = $1::uuid AND ($2 = '' OR provider_id = $2) AND (NOT $3 OR explained_by = '')
		  ORDER BY signed_in_at DESC, fingerprint LIMIT $4`, tenantID, providerID, unexplainedOnly, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r PAMSignInRecord
			if err := rows.Scan(&r.ProviderID, &r.Fingerprint, &r.Account, &r.At, &r.Earliest, &r.Source, &r.Method, &r.KeyID, &r.Ref,
				&r.ExplainedBy, &r.ExplainedRef, &r.Collector, &r.RunID, &r.SeenAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListTenantsWithPAMSignInsBefore lists the tenants holding sign-ins from
// before a time, for the retention purge.
func (s *Store) ListTenantsWithPAMSignInsBefore(ctx context.Context, before time.Time, limit int) ([]string, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — the sign-in retention purge finds every tenant holding sign-ins past the deployment's horizon; each purge is then appended under its own tenant's context.
		`SELECT DISTINCT tenant_id::text FROM pam_signin_records WHERE signed_in_at < $1 LIMIT $2`, before.UTC(), limit)
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
