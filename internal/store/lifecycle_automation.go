// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// LifecycleAutomationInventory is the bounded, public-metadata-only read model
// behind the lifecycle automation plan. The issuance key remains server-internal:
// it proves a first issuance receipt for the same scheduler decision and is never
// serialized to the console. Certificate DER and outbox payloads are excluded.
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
	CertificateCreatedAt      time.Time
	CertificateIssuanceKey    string
	LatestRunID               string
	LatestRunStatus           string
	RollbackRef               string
	PendingRenewal            bool
	// DeliveryUnverified means an identity has an issued certificate and a
	// failed connector delivery for it, but no successful served-certificate
	// receipt. The plan may show this row; the scheduler must not renew it.
	DeliveryUnverified bool
	TargetID           string
	PredecessorID      string
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
			       cert.created_at, cert.issuance_idempotency_key,
			       coalesce(run.id::text, ''), coalesce(run.status, ''), coalesce(run.rollback_ref, ''),
			       coalesce(i.attributes->>'deployment_target_id', ''),
			       coalesce(i.attributes->>'endpoint_replaces_identity_id', ''),
			       unverified.fingerprint IS NOT NULL,
			       EXISTS (SELECT 1 FROM outbox job WHERE job.tenant_id = $1 AND job.tenant_id = i.tenant_id
			         AND job.status IN ('pending', 'processing')
			         AND CASE WHEN job.destination IN ('ca.renew', 'endpoint.renew')
			         THEN convert_from(job.payload, 'UTF8')::jsonb->>'identity_id' = i.id::text ELSE false END)
			  FROM identities AS i
			  JOIN owners AS o
			    ON o.tenant_id = $1 AND o.tenant_id = i.tenant_id AND o.id = i.owner_id
			  LEFT JOIN LATERAL (
			       SELECT receipt.fingerprint, receipt.updated_at
			         FROM connector_delivery_receipts receipt
			         JOIN certificates served
			           ON served.tenant_id = $1 AND served.tenant_id = receipt.tenant_id
			          AND served.fingerprint = receipt.fingerprint
			          AND (served.source = 'issued' OR served.issuance_idempotency_key <> '')
			        WHERE receipt.tenant_id = $1 AND receipt.tenant_id = i.tenant_id
			          AND receipt.identity_id = i.id
			          AND ((receipt.destination = 'connector.deploy' AND receipt.status IN ('delivered', 'verified') AND served.status = 'active'
			            AND receipt.reason <> 'agent_delivered_verification_failed'
			            AND NOT EXISTS (SELECT 1 FROM connector_delivery_receipts failed
			              WHERE failed.tenant_id = $1 AND failed.tenant_id = receipt.tenant_id
			                AND failed.identity_id = receipt.identity_id
			                AND failed.destination = 'connector.deploy' AND failed.status = 'verify_failed'
			                AND failed.idempotency_key = receipt.idempotency_key || ':verified'))
			            OR (receipt.destination = 'connector.rollback' AND receipt.status = 'rolled_back' AND served.status IN ('active', 'superseded')))
			        ORDER BY receipt.updated_at DESC, receipt.id DESC LIMIT 1
		  ) AS deployed ON true
		  LEFT JOIN LATERAL (
		       SELECT receipt.fingerprint
		         FROM connector_delivery_receipts receipt
		         JOIN certificates candidate
		           ON candidate.tenant_id = $1 AND candidate.tenant_id = receipt.tenant_id
		          AND candidate.fingerprint = receipt.fingerprint
		          AND (candidate.source = 'issued' OR candidate.issuance_idempotency_key <> '') AND candidate.status = 'active'
		          AND candidate.owner_id = i.owner_id AND i.name = ANY(candidate.sans)
		        WHERE receipt.tenant_id = $1 AND receipt.tenant_id = i.tenant_id
		          AND receipt.identity_id = i.id
		          AND receipt.destination = 'connector.deploy'
		          AND receipt.status IN ('failed', 'verify_failed')
		          AND (deployed.updated_at IS NULL OR receipt.updated_at > deployed.updated_at)
		        ORDER BY receipt.updated_at DESC, receipt.id DESC LIMIT 1
		  ) AS unverified ON true
		  JOIN LATERAL (
			       SELECT c.id, c.not_before, c.not_after, c.validity_anchor,
			              c.created_at, c.issuance_idempotency_key
			         FROM certificates AS c
			        WHERE c.tenant_id = $1
			          AND c.tenant_id = i.tenant_id
		          AND ((deployed.fingerprint IS NOT NULL AND c.fingerprint = deployed.fingerprint)
		            OR (deployed.fingerprint IS NULL AND unverified.fingerprint IS NOT NULL
		                AND c.fingerprint = unverified.fingerprint)
		            OR (deployed.fingerprint IS NULL AND NOT EXISTS (
			                  SELECT 1 FROM connector_delivery_receipts prior
			                   WHERE prior.tenant_id = $1 AND prior.tenant_id = i.tenant_id
			                     AND prior.identity_id = i.id)
			                AND c.status = 'active' AND c.owner_id = i.owner_id AND i.name = ANY(c.sans)))
			          AND (c.source = 'issued' OR c.issuance_idempotency_key <> '')
			          AND c.status IN ('active', 'superseded')
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
			   AND NOT EXISTS (SELECT 1 FROM identities replacement
			     WHERE replacement.tenant_id = $1 AND replacement.tenant_id = i.tenant_id
			       AND replacement.attributes->>'endpoint_replaces_identity_id' = i.id::text
			       AND replacement.status IN ('issued', 'deployed', 'renewing', 'renewal_failed'))
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
				&item.CertificateCreatedAt, &item.CertificateIssuanceKey,
				&item.LatestRunID, &item.LatestRunStatus, &item.RollbackRef,
				&item.TargetID, &item.PredecessorID, &item.DeliveryUnverified,
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
