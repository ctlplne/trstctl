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
		rows, err := tx.Query(ctx, `WITH selected AS MATERIALIZED (
            SELECT id, fingerprint, issuance_idempotency_key FROM certificates
            WHERE tenant_id=$1 AND id=ANY($2::uuid[])
        ), retained_transitions AS MATERIALIZED (
            SELECT identity_id, CASE event_type
             WHEN 'identity.issued' THEN 'issue:transition:' || idempotency_key
             WHEN 'identity.renewing' THEN 'renew:transition:' || idempotency_key END AS request_key
            FROM identity_transitions WHERE tenant_id=$1 AND idempotency_key <> ''
             AND event_type IN ('identity.issued','identity.renewing')
        ), retained_jobs AS MATERIALIZED (
            SELECT id::text AS job_id, destination, required_agent_role, payload,
             CASE destination WHEN 'ca.issue' THEN 'issue:' || idempotency_key
              WHEN 'ca.renew' THEN 'renew:' || idempotency_key END AS request_key
            FROM outbox WHERE tenant_id=$1 AND destination IN ('ca.issue','ca.renew','endpoint.renew')
        ), matching_jobs AS MATERIALIZED (
            SELECT c.id AS certificate_id, j.payload FROM selected c
            JOIN retained_jobs j ON c.issuance_idempotency_key=j.request_key
            WHERE j.destination IN ('ca.issue','ca.renew')
            UNION ALL
            SELECT c.id, j.payload FROM selected c
            JOIN retained_jobs j ON j.destination='endpoint.renew'
             AND j.required_agent_role='host'
             AND split_part(c.issuance_idempotency_key,':',2)=j.job_id
            WHERE c.issuance_idempotency_key LIKE 'agentcsr:%:%'
        ), bindings AS MATERIALIZED (
            SELECT c.id AS certificate_id, t.identity_id::text FROM selected c
            JOIN retained_transitions t ON c.issuance_idempotency_key=t.request_key
            UNION ALL
            SELECT c.id, r.identity_id::text FROM selected c
            JOIN connector_delivery_receipts r ON r.tenant_id=$1 AND r.fingerprint=c.fingerprint
            WHERE r.identity_id IS NOT NULL AND (
             (r.destination='connector.deploy' AND r.status IN ('delivered','verified'))
             OR (r.destination='connector.rollback' AND r.status='rolled_back'))
            UNION ALL
            SELECT j.certificate_id, convert_from(j.payload,'UTF8')::jsonb->>'identity_id' FROM matching_jobs j
        )
        , eligible_identities AS MATERIALIZED (SELECT id::text AS id FROM identities WHERE tenant_id=$1 AND kind IN ('x509_certificate','x509'))
        SELECT DISTINCT b.certificate_id::text, i.id FROM bindings b
        JOIN eligible_identities i ON i.id=b.identity_id
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
