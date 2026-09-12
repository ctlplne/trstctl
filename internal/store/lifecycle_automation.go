// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// LifecycleAutomationInventory is the bounded, public-metadata-only read model
// behind the lifecycle automation plan. It deliberately excludes certificate DER,
// outbox payloads, and idempotency keys: the console needs to know what will run,
// not receive the credential-bearing command.
type LifecycleAutomationInventory struct {
	IdentityID                string
	IdentityName              string
	IdentityStatus            string
	OwnerID                   string
	OwnerName                 string
	CertificateID             string
	CertificateStart          *time.Time
	CertificateEnd            *time.Time
	CertificateValidityAnchor *time.Time
	LatestRunID               string
	LatestRunStatus           string
	RollbackRef               string
	PendingRenewal            bool
}

// LifecycleAutomationOutboxSummary reports only aggregate command state for the
// lifecycle destinations. No outbox payload crosses this read boundary.
type LifecycleAutomationOutboxSummary struct {
	Pending    int
	Processing int
	Failed     int
}

// ListLifecycleAutomationInventory returns at most limit renewable X.509
// identities and their newest immutable rotation evidence for one tenant. Every
// table reference is explicitly tenant-bound in addition to RLS (AN-1).
// Certificate selection matches LatestDeployedCertificateFingerprintForIdentity:
// prefer exact successful delivery or restore evidence, with owner/SAN fallback only for
// legacy identities that have no such receipt. The bounded list stays one query.
func (s *Store) ListLifecycleAutomationInventory(ctx context.Context, tenantID string, limit int) ([]LifecycleAutomationInventory, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	var out []LifecycleAutomationInventory
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT i.id::text, i.name, i.status, i.owner_id::text, o.name,
			       cert.id::text, cert.not_before, cert.not_after, cert.validity_anchor,
			       coalesce(run.id::text, ''), coalesce(run.status, ''), coalesce(run.rollback_ref, ''),
			       EXISTS (SELECT 1 FROM outbox job WHERE job.tenant_id = $1 AND job.tenant_id = i.tenant_id
			         AND job.status IN ('pending', 'processing')
			         AND CASE WHEN job.destination IN ('ca.renew', 'endpoint.renew')
			         THEN convert_from(job.payload, 'UTF8')::jsonb->>'identity_id' = i.id::text ELSE false END)
			  FROM identities AS i
			  JOIN owners AS o
			    ON o.tenant_id = $1 AND o.tenant_id = i.tenant_id AND o.id = i.owner_id
			  LEFT JOIN LATERAL (
			       SELECT receipt.fingerprint
			         FROM connector_delivery_receipts receipt
			         JOIN certificates served
			           ON served.tenant_id = $1 AND served.tenant_id = receipt.tenant_id
			          AND served.fingerprint = receipt.fingerprint
			          AND served.source = 'issued' AND served.status = 'active'
			        WHERE receipt.tenant_id = $1 AND receipt.tenant_id = i.tenant_id
			          AND receipt.identity_id = i.id
			          AND ((receipt.destination = 'connector.deploy' AND receipt.status IN ('delivered', 'verified'))
			            OR (receipt.destination = 'connector.rollback' AND receipt.status = 'rolled_back'))
			        ORDER BY receipt.updated_at DESC, receipt.id DESC LIMIT 1
			  ) AS deployed ON true
			  JOIN LATERAL (
			       SELECT c.id, c.not_before, c.not_after, c.validity_anchor
			         FROM certificates AS c
			        WHERE c.tenant_id = $1
			          AND c.tenant_id = i.tenant_id
			          AND ((deployed.fingerprint IS NOT NULL AND c.fingerprint = deployed.fingerprint)
			            OR (deployed.fingerprint IS NULL AND c.owner_id = i.owner_id AND i.name = ANY(c.sans)))
			          AND c.source = 'issued'
			          AND c.status = 'active'
			        ORDER BY c.not_after DESC NULLS LAST, c.created_at DESC, c.id
			        LIMIT 1
			  ) AS cert ON true
			  LEFT JOIN LATERAL (
			       SELECT r.id, r.status, r.rollback_ref
			         FROM lifecycle_rotation_runs AS r
			        WHERE r.tenant_id = $1
			          AND r.tenant_id = i.tenant_id
			          AND r.identity_id = i.id
			        ORDER BY r.updated_at DESC, r.id DESC
			        LIMIT 1
			  ) AS run ON true
			 WHERE i.tenant_id = $1
			   AND i.kind = 'x509_certificate'
			   AND i.status IN ('deployed', 'renewing', 'renewal_failed')
			 ORDER BY cert.not_after ASC NULLS LAST, i.id
			 LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item LifecycleAutomationInventory
			if err := rows.Scan(
				&item.IdentityID, &item.IdentityName, &item.IdentityStatus,
				&item.OwnerID, &item.OwnerName, &item.CertificateID,
				&item.CertificateStart, &item.CertificateEnd, &item.CertificateValidityAnchor,
				&item.LatestRunID, &item.LatestRunStatus, &item.RollbackRef,
				&item.PendingRenewal,
			); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

// GetLifecycleAutomationOutboxSummary counts only lifecycle destinations for one
// tenant. It never selects payload, last_error, or idempotency material.
func (s *Store) GetLifecycleAutomationOutboxSummary(ctx context.Context, tenantID string) (LifecycleAutomationOutboxSummary, error) {
	var summary LifecycleAutomationOutboxSummary
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE status = 'pending'),
			       count(*) FILTER (WHERE status = 'processing'),
			       count(*) FILTER (WHERE status = 'failed')
			  FROM outbox
			 WHERE tenant_id = $1
			   AND destination = ANY($2::text[])`, tenantID,
			[]string{"ca.renew", "endpoint.renew", "connector.deploy", "notification.expiry"}).Scan(
			&summary.Pending, &summary.Processing, &summary.Failed)
	})
	return summary, err
}
