// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// CertificateIdentityBindings resolves a bounded inventory page from retained
// issuance and successful delivery evidence. Names, owners, SANs and mutable
// identity attributes are not binding evidence. Multiple identities are returned
// explicitly; a caller must not arbitrarily choose one for a lifecycle mutation.
func (s *Store) CertificateIdentityBindings(ctx context.Context, tenantID string, certificateIDs []string) (map[string][]string, error) {
	result := make(map[string][]string)
	if len(certificateIDs) == 0 {
		return result, nil
	}
	if len(certificateIDs) > 1000 {
		return nil, fmt.Errorf("store: certificate binding page exceeds 1000 records")
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `WITH selected AS (
			SELECT id, fingerprint, issuance_idempotency_key FROM certificates
			WHERE tenant_id=$1 AND id=ANY($2::uuid[])
		), bindings AS (
			SELECT c.id AS certificate_id, t.identity_id
			FROM selected c JOIN identity_transitions t ON t.tenant_id=$1
			 AND t.idempotency_key <> '' AND (
			  (t.event_type='identity.issued' AND c.issuance_idempotency_key='issue:transition:' || t.idempotency_key)
			  OR (t.event_type='identity.renewing' AND c.issuance_idempotency_key='renew:transition:' || t.idempotency_key))
			UNION
			SELECT c.id, r.identity_id FROM selected c
			JOIN connector_delivery_receipts r ON r.tenant_id=$1 AND r.fingerprint=c.fingerprint
			WHERE r.identity_id IS NOT NULL AND (
			 (r.destination='connector.deploy' AND r.status IN ('delivered','verified'))
			 OR (r.destination='connector.rollback' AND r.status='rolled_back'))
			UNION
			SELECT c.id, i.id FROM selected c JOIN outbox j ON j.tenant_id=$1 AND (
			 (j.destination='ca.issue' AND c.issuance_idempotency_key='issue:' || j.idempotency_key)
			 OR (j.destination='ca.renew' AND c.issuance_idempotency_key='renew:' || j.idempotency_key)
			 OR (j.destination='endpoint.renew' AND j.required_agent_role='host'
			  AND c.issuance_idempotency_key LIKE 'agentcsr:' || j.id::text || ':%'))
			JOIN identities i ON i.tenant_id=$1 AND i.id::text=CASE
			 WHEN j.destination IN ('ca.issue','ca.renew','endpoint.renew')
			 THEN convert_from(j.payload,'UTF8')::jsonb->>'identity_id' END
		)
		SELECT DISTINCT b.certificate_id::text, i.id::text FROM bindings b
		JOIN identities i ON i.tenant_id=$1 AND i.id=b.identity_id AND i.kind IN ('x509_certificate','x509')
		ORDER BY b.certificate_id::text, i.id::text`, tenantID, certificateIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var certificateID, identityID string
			if err := rows.Scan(&certificateID, &identityID); err != nil {
				return err
			}
			result[certificateID] = append(result[certificateID], identityID)
		}
		return rows.Err()
	})
	return result, err
}
