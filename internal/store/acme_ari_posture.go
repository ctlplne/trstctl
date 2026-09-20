// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"
)

// ACMEARIPostureRow is the tenant-scoped store input for the operator-visible
// ARI posture. CertificateDER is used only inside the server to derive the
// public RFC 9773 certificate identifier; it is never returned by the REST
// surface. Rotation reason and fingerprint likewise stay internal and let the
// server distinguish an ARI scheduler decision from the fixed-expiry fallback.
type ACMEARIPostureRow struct {
	CertificateID      string
	IdentityID         string
	IdentityName       string
	CertificateStatus  string
	Fingerprint        string
	NotBefore          *time.Time
	NotAfter           time.Time
	CertificateDER     []byte
	RotationRunID      string
	RotationRunStatus  string
	RotationRunTrigger string
	RotationRunReason  string
	RotationRunCreated *time.Time
}

// ListACMEARIPosturePage returns active certificates and consumed predecessors
// that can participate in either side of ARI: certificates actually issued by
// the served ACME protocol, and internally-issued certificates associated with
// a deployed lifecycle identity. The query deliberately keeps superseded
// predecessors because that row is the durable evidence that the scheduler
// consumed a suggested window.
func (s *Store) ListACMEARIPosturePage(ctx context.Context, tenantID, afterID string, limit int) ([]ACMEARIPostureRow, error) {
	var out []ACMEARIPostureRow
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT c.id::text,
			        COALESCE(i.id::text, ''),
			        COALESCE(i.name, ''),
			        c.status,
			        c.fingerprint,
			        c.not_before,
			        c.not_after,
			        c.certificate_der,
			        COALESCE(ari_rr.id::text, rr.id::text, ''),
			        COALESCE(ari_rr.status, rr.status, ''),
			        COALESCE(ari_rr.trigger, rr.trigger, ''),
			        COALESCE(ari_rr.reason, rr.reason, ''),
			        COALESCE(ari_rr.created_at, rr.created_at)
			   FROM certificates c
			   LEFT JOIN LATERAL (
			        SELECT run.id, run.identity_id, run.status, run.trigger, run.reason, run.created_at
			          FROM lifecycle_rotation_runs run
			         WHERE run.tenant_id = $1
			           AND run.predecessor_fingerprint = c.fingerprint
			           AND run.trigger = 'scheduler'
			           AND run.reason LIKE 'scheduled renewal from ARI window %'
			         ORDER BY run.updated_at DESC, run.id DESC
			         LIMIT 1
			   ) ari_rr ON TRUE
			   LEFT JOIN LATERAL (
			        SELECT run.id, run.identity_id, run.status, run.trigger, run.reason, run.created_at
			          FROM lifecycle_rotation_runs run
			         WHERE run.tenant_id = $1
			           AND run.predecessor_fingerprint = c.fingerprint
			         ORDER BY run.updated_at DESC, run.id DESC
			         LIMIT 1
			   ) rr ON TRUE
			   LEFT JOIN LATERAL (
			        SELECT ident.id, ident.name
			          FROM identities ident
			         WHERE ident.tenant_id = $1
			           AND (
			                (
			                 COALESCE(ari_rr.identity_id, rr.identity_id) IS NOT NULL
			                 AND ident.id = COALESCE(ari_rr.identity_id, rr.identity_id)
			                )
			                OR (
			                    COALESCE(ari_rr.identity_id, rr.identity_id) IS NULL
			                    AND ident.kind = 'x509_certificate'
			                    AND ident.owner_id = c.owner_id
			                    AND ident.name = ANY(c.sans)
			                   )
			               )
			         ORDER BY
			           CASE WHEN ident.id = COALESCE(ari_rr.identity_id, rr.identity_id) THEN 0 ELSE 1 END,
			           CASE ident.status WHEN 'deployed' THEN 0 WHEN 'renewing' THEN 1 WHEN 'renewal_failed' THEN 2 ELSE 3 END,
			           ident.created_at DESC,
			           ident.id
			         LIMIT 1
			   ) i ON TRUE
			  WHERE c.tenant_id = $1
			    AND c.id > $2
			    AND c.status IN ('active', 'superseded', 'revoked')
			    AND c.not_after IS NOT NULL
			    AND (
			         c.source = 'protocol:acme'
			         OR (
			             c.source = 'issued'
			             AND (i.id IS NOT NULL OR ari_rr.id IS NOT NULL OR rr.id IS NOT NULL)
			            )
			        )
			  ORDER BY c.id
			  LIMIT $3`,
			tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				row           ACMEARIPostureRow
				notBefore     sql.NullTime
				rotationStart sql.NullTime
			)
			if err := rows.Scan(
				&row.CertificateID,
				&row.IdentityID,
				&row.IdentityName,
				&row.CertificateStatus,
				&row.Fingerprint,
				&notBefore,
				&row.NotAfter,
				&row.CertificateDER,
				&row.RotationRunID,
				&row.RotationRunStatus,
				&row.RotationRunTrigger,
				&row.RotationRunReason,
				&rotationStart,
			); err != nil {
				return err
			}
			if notBefore.Valid {
				t := notBefore.Time
				row.NotBefore = &t
			}
			if rotationStart.Valid {
				t := rotationStart.Time
				row.RotationRunCreated = &t
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}
