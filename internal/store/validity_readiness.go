// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ValidityReadinessLimit bounds the certificates one validity-readiness report
// evaluates.
const ValidityReadinessLimit = 5000

// ListValidityReadinessCertificates returns the tenant's active, unexpired
// certificates in expiry order, at most ValidityReadinessLimit, and whether
// there were more. Ephemeral certificates, issued per use and never renewed,
// are left out as the expiry views leave them out. Tenant-scoped under RLS
// (AN-1).
func (s *Store) ListValidityReadinessCertificates(ctx context.Context, tenantID string, now time.Time) ([]Certificate, bool, error) {
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+certificateColumns+`
			   FROM certificates
			  WHERE tenant_id = $1 AND status = 'active' AND not_after > $2
			    AND issuance_idempotency_key NOT LIKE 'ephemeral-issue:%'
			  ORDER BY not_after, id LIMIT $3`,
			tenantID, now, ValidityReadinessLimit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Certificate
			if err := scanCertificate(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	truncated := len(out) > ValidityReadinessLimit
	if truncated {
		out = out[:ValidityReadinessLimit]
	}
	return out, truncated, nil
}
