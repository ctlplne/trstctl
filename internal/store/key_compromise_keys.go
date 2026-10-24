// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// KeyCompromiseRevokedCertificates returns the DER of at most limit of the
// tenant's certificates revoked with reason keyCompromise, so issuance can
// refuse a subject key one of them carried (CA/B BR 6.1.1.3, condition 4).
// The read runs inside the tenant's RLS scope (AN-1).
func (s *Store) KeyCompromiseRevokedCertificates(ctx context.Context, tenantID string, limit int) ([][]byte, error) {
	var out [][]byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT certificate_der FROM certificates
		  WHERE tenant_id = $1 AND revocation_reason = 'keyCompromise' AND octet_length(certificate_der) > 0
		  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var der []byte
			if err := rows.Scan(&der); err != nil {
				return err
			}
			out = append(out, der)
		}
		return rows.Err()
	})
	return out, err
}
