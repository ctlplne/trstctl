// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

const identityRevocationBinding = `(
    EXISTS (SELECT 1 FROM connector_delivery_receipts r
     WHERE r.tenant_id=$1 AND r.identity_id=$2 AND r.fingerprint=certificates.fingerprint
      AND ((r.destination='connector.deploy' AND r.status IN ('delivered','verified'))
       OR (r.destination='connector.rollback' AND r.status='rolled_back')))
    OR EXISTS (SELECT 1 FROM identity_transitions t
     WHERE t.tenant_id=$1 AND t.identity_id=$2
      AND ((t.event_type='identity.issued'
       AND certificates.issuance_idempotency_key='issue:transition:' || t.idempotency_key)
       OR (t.event_type='identity.renewing'
       AND certificates.issuance_idempotency_key='renew:transition:' || t.idempotency_key)))
    OR EXISTS (SELECT 1 FROM outbox j
     WHERE j.tenant_id=$1 AND j.destination IN ('ca.issue','ca.renew','endpoint.renew')
      AND convert_from(j.payload,'UTF8')::jsonb->>'identity_id'=$2::text
      AND ((j.destination='endpoint.renew' AND j.required_agent_role='host'
       AND certificates.issuance_idempotency_key LIKE 'agentcsr:' || j.id::text || ':%')
       OR (j.destination='ca.issue' AND certificates.issuance_idempotency_key='issue:' || j.idempotency_key)
       OR (j.destination='ca.renew' AND certificates.issuance_idempotency_key='renew:' || j.idempotency_key)))
   )`

// IdentityRevocationCertificates follows exact issuance or delivery evidence.
// Owner/SAN similarity is not authority to revoke a different identity's leaf.
// Superseded certificates remain candidates: rollback can make them serve again.
// The caller drains bounded pages by recording confirmed revocations as events.
func (s *Store) IdentityRevocationCertificates(ctx context.Context, tenantID, identityID string, limit int) ([]Certificate, error) {
	if limit <= 0 || limit > 101 {
		limit = 101
	}
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+certificateColumns+` FROM certificates
   WHERE tenant_id=$1 AND status <> 'revoked' AND `+identityRevocationBinding+`
   ORDER BY created_at,id LIMIT $3`, tenantID, identityID, limit)
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
	return out, err
}

// Distinguish a completed retry from a missing identity/certificate binding.
// Similar owner or subject text cannot justify reporting zero-leaf completion.
func (s *Store) IdentityHasRevocationEvidence(ctx context.Context, tenantID, identityID string) (bool, error) {
	var found bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificates
   WHERE tenant_id=$1 AND `+identityRevocationBinding+`)`, tenantID, identityID).Scan(&found)
	})
	return found, err
}
