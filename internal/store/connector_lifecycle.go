// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConnectorDeliveryReceipt is the projected evidence for one connector.deploy
// outbox row. It deliberately contains no certificate or private-key bytes.
type ConnectorDeliveryReceipt struct {
	ID             string
	TenantID       string
	OutboxID       *int64
	IdentityID     *string
	Destination    string
	Connector      string
	Target         string
	Fingerprint    string
	Status         string
	Attempts       int
	Reason         string
	Detail         string
	RollbackRef    string
	IdempotencyKey string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RotationRun is the projected evidence for one lifecycle renewal/rotation
// outbox row, including enough rollback metadata for an operator to tie the
// successor back to the retired public certificate.
type RotationRun struct {
	ID                     string
	TenantID               string
	IdentityID             string
	OutboxID               *int64
	Status                 string
	Trigger                string
	Reason                 string
	PredecessorFingerprint string
	SuccessorFingerprint   string
	RollbackRef            string
	Error                  string
	IdempotencyKey         string
	CreatedAt              time.Time
	UpdatedAt              time.Time
	CompletedAt            *time.Time
}

// ApplyConnectorDeliveryRecordedTx projects a connector.delivery.recorded event.
// Repeated attempts for the same delivery id update the same row, so retries
// converge instead of creating misleading duplicate receipts.
func (s *Store) ApplyConnectorDeliveryRecordedTx(ctx context.Context, tx pgx.Tx, r ConnectorDeliveryReceipt) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO connector_delivery_receipts
		        (id, tenant_id, outbox_id, identity_id, destination, connector, target,
		         fingerprint, status, attempts, reason, detail, rollback_ref,
		         idempotency_key, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		 ON CONFLICT (id) DO UPDATE
		    SET outbox_id = EXCLUDED.outbox_id,
		        identity_id = EXCLUDED.identity_id,
		        destination = EXCLUDED.destination,
		        connector = EXCLUDED.connector,
		        target = EXCLUDED.target,
		        fingerprint = EXCLUDED.fingerprint,
		        status = EXCLUDED.status,
		        attempts = EXCLUDED.attempts,
		        reason = EXCLUDED.reason,
		        detail = EXCLUDED.detail,
		        rollback_ref = EXCLUDED.rollback_ref,
		        idempotency_key = EXCLUDED.idempotency_key,
		        updated_at = EXCLUDED.updated_at`,
		r.ID, r.TenantID, r.OutboxID, r.IdentityID, r.Destination, r.Connector, r.Target,
		r.Fingerprint, r.Status, r.Attempts, r.Reason, r.Detail, r.RollbackRef,
		r.IdempotencyKey, r.CreatedAt, r.UpdatedAt)
	return err
}

// ApplyRotationRunRecordedTx projects a lifecycle.rotation.recorded event.
func (s *Store) ApplyRotationRunRecordedTx(ctx context.Context, tx pgx.Tx, r RotationRun) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO lifecycle_rotation_runs
		        (id, tenant_id, identity_id, outbox_id, status, trigger, reason,
		         predecessor_fingerprint, successor_fingerprint, rollback_ref, error,
		         idempotency_key, created_at, updated_at, completed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (id) DO UPDATE
		    SET identity_id = EXCLUDED.identity_id,
		        outbox_id = EXCLUDED.outbox_id,
		        status = EXCLUDED.status,
		        trigger = EXCLUDED.trigger,
		        reason = EXCLUDED.reason,
		        predecessor_fingerprint = EXCLUDED.predecessor_fingerprint,
		        successor_fingerprint = EXCLUDED.successor_fingerprint,
		        rollback_ref = EXCLUDED.rollback_ref,
		        error = EXCLUDED.error,
		        idempotency_key = EXCLUDED.idempotency_key,
		        updated_at = EXCLUDED.updated_at,
		        completed_at = EXCLUDED.completed_at`,
		r.ID, r.TenantID, r.IdentityID, r.OutboxID, r.Status, r.Trigger, r.Reason,
		r.PredecessorFingerprint, r.SuccessorFingerprint, r.RollbackRef, r.Error,
		r.IdempotencyKey, r.CreatedAt, r.UpdatedAt, r.CompletedAt)
	return err
}

func scanConnectorDeliveryReceipt(row pgx.Row, r *ConnectorDeliveryReceipt) error {
	var (
		outboxID   sql.NullInt64
		identityID sql.NullString
	)
	err := row.Scan(&r.ID, &r.TenantID, &outboxID, &identityID, &r.Destination, &r.Connector,
		&r.Target, &r.Fingerprint, &r.Status, &r.Attempts, &r.Reason, &r.Detail,
		&r.RollbackRef, &r.IdempotencyKey, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return err
	}
	if outboxID.Valid {
		r.OutboxID = &outboxID.Int64
	}
	if identityID.Valid {
		r.IdentityID = &identityID.String
	}
	return nil
}

func scanRotationRun(row pgx.Row, r *RotationRun) error {
	var outboxID sql.NullInt64
	err := row.Scan(&r.ID, &r.TenantID, &r.IdentityID, &outboxID, &r.Status, &r.Trigger, &r.Reason,
		&r.PredecessorFingerprint, &r.SuccessorFingerprint, &r.RollbackRef, &r.Error,
		&r.IdempotencyKey, &r.CreatedAt, &r.UpdatedAt, &r.CompletedAt)
	if err != nil {
		return err
	}
	if outboxID.Valid {
		r.OutboxID = &outboxID.Int64
	}
	return nil
}

// ListConnectorDeliveryReceiptsPage returns delivery receipts for one tenant.
func (s *Store) ListConnectorDeliveryReceiptsPage(ctx context.Context, tenantID, identityID, afterID string, limit int) ([]ConnectorDeliveryReceipt, error) {
	var out []ConnectorDeliveryReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, outbox_id, identity_id::text, destination,
			        connector, target, fingerprint, status, attempts, reason, detail,
			        rollback_ref, idempotency_key, created_at, updated_at
			   FROM connector_delivery_receipts
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3 = '' OR identity_id::text = $3)
			  ORDER BY id
			  LIMIT $4`, tenantID, afterID, identityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ConnectorDeliveryReceipt
			if err := scanConnectorDeliveryReceipt(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetConnectorDeliveryReceipt loads one receipt in its tenant context.
func (s *Store) GetConnectorDeliveryReceipt(ctx context.Context, tenantID, id string) (ConnectorDeliveryReceipt, error) {
	var r ConnectorDeliveryReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanConnectorDeliveryReceipt(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, outbox_id, identity_id::text, destination,
			        connector, target, fingerprint, status, attempts, reason, detail,
			        rollback_ref, idempotency_key, created_at, updated_at
			   FROM connector_delivery_receipts
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &r)
	})
	return r, err
}

// ListRotationRunsPage returns rotation/renewal runs for one tenant.
func (s *Store) ListRotationRunsPage(ctx context.Context, tenantID, identityID, afterID string, limit int) ([]RotationRun, error) {
	var out []RotationRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, identity_id::text, outbox_id, status, trigger, reason,
			        predecessor_fingerprint, successor_fingerprint, rollback_ref, error,
			        idempotency_key, created_at, updated_at, completed_at
			   FROM lifecycle_rotation_runs
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3 = '' OR identity_id::text = $3)
			  ORDER BY id
			  LIMIT $4`, tenantID, afterID, identityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r RotationRun
			if err := scanRotationRun(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetRotationRun loads one lifecycle rotation run in its tenant context.
func (s *Store) GetRotationRun(ctx context.Context, tenantID, id string) (RotationRun, error) {
	var r RotationRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanRotationRun(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, identity_id::text, outbox_id, status, trigger, reason,
			        predecessor_fingerprint, successor_fingerprint, rollback_ref, error,
			        idempotency_key, created_at, updated_at, completed_at
			   FROM lifecycle_rotation_runs
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &r)
	})
	return r, err
}

// ListRenewableIdentities returns deployed X.509 identities whose active served
// certificates expire before cutoff. The scheduler uses this to queue the normal
// deployed->renewing transition, so renewal still travels through the outbox.
func (s *Store) ListRenewableIdentities(ctx context.Context, tenantID string, cutoff time.Time) ([]Identity, error) {
	var out []Identity
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT ON (i.id) i.id::text, i.tenant_id::text, i.kind, i.name, i.owner_id::text,
			        i.issuer_id::text, i.status, i.not_before, i.not_after, i.attributes, i.created_at
			   FROM identities i
			   JOIN certificates c
			     ON c.tenant_id = i.tenant_id
			    AND c.owner_id = i.owner_id
			    AND i.name = ANY(c.sans)
			  WHERE i.tenant_id = $1
			    AND i.kind = 'x509_certificate'
			    AND i.status = 'deployed'
			    AND c.source = 'issued'
			    AND c.status = 'active'
			    AND c.not_after IS NOT NULL
			    AND c.not_after < $2
			  ORDER BY i.id, i.created_at`, tenantID, cutoff)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				it    Identity
				kind  string
				attrs []byte
			)
			if err := rows.Scan(&it.ID, &it.TenantID, &kind, &it.Name, &it.OwnerID, &it.IssuerID,
				&it.Status, &it.NotBefore, &it.NotAfter, &attrs, &it.CreatedAt); err != nil {
				return err
			}
			it.Kind = IdentityKind(kind)
			it.Attributes = attrs
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}

// RenewalIdentityCandidate is the scheduler input for one deployed X.509
// identity and the active internally-issued certificate that makes it renewable.
// The server consumes the certificate validity span through the ARI package, so
// the renewal decision stays aligned with ACME Renewal Information rather than a
// fixed expiry cutoff alone.
type RenewalIdentityCandidate struct {
	Identity    Identity
	Certificate Certificate
}

// ListRenewalIdentityCandidates returns deployed X.509 identities whose active
// served certificates are eligible for a scheduler decision. Eligibility is a
// coarse database prefilter: either the old fixed cutoff is already reached, or
// the normal ARI suggested-window start has reached ariNow. The server still
// recomputes the final decision with internal/protocols/ari before mutating
// lifecycle state.
func (s *Store) ListRenewalIdentityCandidates(ctx context.Context, tenantID string, fixedCutoff, ariNow time.Time) ([]RenewalIdentityCandidate, error) {
	var out []RenewalIdentityCandidate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT ON (i.id)
			        i.id::text, i.tenant_id::text, i.kind, i.name, i.owner_id::text,
			        i.issuer_id::text, i.status, i.not_before, i.not_after, i.attributes, i.created_at,
			        c.id::text, c.tenant_id::text, c.owner_id::text, c.subject, c.sans, c.issuer, c.serial,
			        c.fingerprint, c.key_algorithm, c.not_before, c.not_after, c.deployment_location, c.source,
			        c.certificate_der, c.issuance_idempotency_key, c.created_at,
			        c.status, c.replaces_id::text, c.revoked_at, c.revocation_reason, c.renewed_at, c.alerted_at
			   FROM identities i
			   JOIN certificates c
			     ON c.tenant_id = i.tenant_id
			    AND c.owner_id = i.owner_id
			    AND i.name = ANY(c.sans)
			  WHERE i.tenant_id = $1
			    AND i.kind = 'x509_certificate'
			    AND i.status = 'deployed'
			    AND c.source = 'issued'
			    AND c.status = 'active'
			    AND c.not_after IS NOT NULL
			    AND (
			         c.not_after < $2
			         OR (
			              c.not_before IS NOT NULL
			              AND c.not_after - ((c.not_after - c.not_before) / 3.0) <= $3
			            )
			        )
			  ORDER BY i.id, c.not_after, c.created_at`,
			tenantID, fixedCutoff, ariNow)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				it    Identity
				kind  string
				attrs []byte
				cert  Certificate
			)
			if err := rows.Scan(&it.ID, &it.TenantID, &kind, &it.Name, &it.OwnerID, &it.IssuerID,
				&it.Status, &it.NotBefore, &it.NotAfter, &attrs, &it.CreatedAt,
				&cert.ID, &cert.TenantID, &cert.OwnerID, &cert.Subject, &cert.SANs, &cert.Issuer, &cert.Serial,
				&cert.Fingerprint, &cert.KeyAlgorithm, &cert.NotBefore, &cert.NotAfter, &cert.DeploymentLocation, &cert.Source,
				&cert.CertificateDER, &cert.IssuanceIdempotencyKey, &cert.CreatedAt,
				&cert.Status, &cert.ReplacesID, &cert.RevokedAt, &cert.RevocationReason, &cert.RenewedAt, &cert.AlertedAt); err != nil {
				return err
			}
			it.Kind = IdentityKind(kind)
			it.Attributes = attrs
			out = append(out, RenewalIdentityCandidate{Identity: it, Certificate: cert})
		}
		return rows.Err()
	})
	return out, err
}

// TenantsWithRenewableIdentities returns tenant ids that currently have at least
// one deployed X.509 identity eligible for scheduled renewal. It is a system
// enumerator for the leader-only scheduler; each tenant's actual identities are
// then loaded through ListRenewableIdentities under that tenant's RLS context.
func (s *Store) TenantsWithRenewableIdentities(ctx context.Context, cutoff time.Time) ([]string, error) {
	return s.TenantsWithRenewalIdentityCandidates(ctx, cutoff, time.Time{})
}

// TenantsWithRenewalIdentityCandidates returns tenant ids that currently have at
// least one deployed X.509 identity whose active issued certificate should be
// evaluated by the scheduler. It is a system enumerator only: each tenant's rows
// are loaded through ListRenewalIdentityCandidates under tenant-scoped RLS.
func (s *Store) TenantsWithRenewalIdentityCandidates(ctx context.Context, fixedCutoff, ariNow time.Time) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: the leader scheduler enumerates which tenants have renewal work, then re-enters tenant-scoped RLS for the rows themselves.
		`SELECT DISTINCT i.tenant_id::text
		   FROM identities i
		   JOIN certificates c
		     ON c.tenant_id = i.tenant_id
		    AND c.owner_id = i.owner_id
		    AND i.name = ANY(c.sans)
		  WHERE i.kind = 'x509_certificate'
		    AND i.status = 'deployed'
		    AND c.source = 'issued'
		    AND c.status = 'active'
		    AND c.not_after IS NOT NULL
		    AND (
		         c.not_after < $1
		         OR (
		              c.not_before IS NOT NULL
		              AND c.not_after - ((c.not_after - c.not_before) / 3.0) <= $2
		            )
		        )
		  ORDER BY 1`, fixedCutoff, ariNow)
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
