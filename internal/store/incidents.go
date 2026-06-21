package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// IncidentExecution is the projected evidence pack for one served incident
// remediation run. It carries metadata and sealed audit evidence only; credential
// and key bytes never belong in this row.
type IncidentExecution struct {
	ID                    string
	TenantID              string
	CompromisedIdentityID string
	ReplacementIdentityID *string
	ConnectorDeliveryID   *string
	Status                string
	Phase                 string
	Reason                string
	BlastRadius           json.RawMessage
	RevocationStatus      string
	EvidenceBundleFormat  string
	EvidenceBundle        string
	FailedTargets         []string
	RollbackRefs          []string
	IdempotencyKey        string
	CreatedBy             string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// ApplyIncidentExecutionRecordedTx projects an incident.execution.recorded event.
// Retrying the same incident id converges on one row, which keeps replay and
// idempotent HTTP retries deterministic.
func (s *Store) ApplyIncidentExecutionRecordedTx(ctx context.Context, tx pgx.Tx, r IncidentExecution) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO incident_executions
		        (id, tenant_id, compromised_identity_id, replacement_identity_id,
		         connector_delivery_id, status, phase, reason, blast_radius,
		         revocation_status, evidence_bundle_format, evidence_bundle,
		         failed_targets, rollback_refs, idempotency_key, created_by,
		         created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12,
		         $13, $14, $15, $16, $17, $18)
		 ON CONFLICT (id) DO UPDATE
		    SET compromised_identity_id = EXCLUDED.compromised_identity_id,
		        replacement_identity_id = EXCLUDED.replacement_identity_id,
		        connector_delivery_id = EXCLUDED.connector_delivery_id,
		        status = EXCLUDED.status,
		        phase = EXCLUDED.phase,
		        reason = EXCLUDED.reason,
		        blast_radius = EXCLUDED.blast_radius,
		        revocation_status = EXCLUDED.revocation_status,
		        evidence_bundle_format = EXCLUDED.evidence_bundle_format,
		        evidence_bundle = EXCLUDED.evidence_bundle,
		        failed_targets = EXCLUDED.failed_targets,
		        rollback_refs = EXCLUDED.rollback_refs,
		        idempotency_key = EXCLUDED.idempotency_key,
		        created_by = EXCLUDED.created_by,
		        updated_at = EXCLUDED.updated_at`,
		r.ID, r.TenantID, r.CompromisedIdentityID, r.ReplacementIdentityID,
		r.ConnectorDeliveryID, r.Status, r.Phase, r.Reason, jsonbOrEmpty(r.BlastRadius),
		r.RevocationStatus, r.EvidenceBundleFormat, r.EvidenceBundle,
		stringSliceOrEmpty(r.FailedTargets), stringSliceOrEmpty(r.RollbackRefs),
		r.IdempotencyKey, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	return err
}

func scanIncidentExecution(row pgx.Row, r *IncidentExecution) error {
	var (
		replacementID sql.NullString
		deliveryID    sql.NullString
		blastRadius   []byte
	)
	err := row.Scan(&r.ID, &r.TenantID, &r.CompromisedIdentityID, &replacementID, &deliveryID,
		&r.Status, &r.Phase, &r.Reason, &blastRadius, &r.RevocationStatus,
		&r.EvidenceBundleFormat, &r.EvidenceBundle, &r.FailedTargets, &r.RollbackRefs,
		&r.IdempotencyKey, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return err
	}
	if replacementID.Valid {
		r.ReplacementIdentityID = &replacementID.String
	}
	if deliveryID.Valid {
		r.ConnectorDeliveryID = &deliveryID.String
	}
	r.BlastRadius = append(json.RawMessage(nil), blastRadius...)
	if r.FailedTargets == nil {
		r.FailedTargets = []string{}
	}
	if r.RollbackRefs == nil {
		r.RollbackRefs = []string{}
	}
	return nil
}

// ListIncidentExecutionsPage returns served incident execution evidence for one
// tenant, optionally scoped to a compromised identity.
func (s *Store) ListIncidentExecutionsPage(ctx context.Context, tenantID, compromisedIdentityID, afterID string, limit int) ([]IncidentExecution, error) {
	var out []IncidentExecution
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, compromised_identity_id::text,
			        replacement_identity_id::text, connector_delivery_id::text,
			        status, phase, reason, blast_radius, revocation_status,
			        evidence_bundle_format, evidence_bundle, failed_targets,
			        rollback_refs, idempotency_key, created_by, created_at, updated_at
			   FROM incident_executions
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3 = '' OR compromised_identity_id::text = $3)
			  ORDER BY id
			  LIMIT $4`, tenantID, afterID, compromisedIdentityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r IncidentExecution
			if err := scanIncidentExecution(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetIncidentExecution loads one incident execution evidence row in its tenant
// context.
func (s *Store) GetIncidentExecution(ctx context.Context, tenantID, id string) (IncidentExecution, error) {
	var r IncidentExecution
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanIncidentExecution(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, compromised_identity_id::text,
			        replacement_identity_id::text, connector_delivery_id::text,
			        status, phase, reason, blast_radius, revocation_status,
			        evidence_bundle_format, evidence_bundle, failed_targets,
			        rollback_refs, idempotency_key, created_by, created_at, updated_at
			   FROM incident_executions
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &r)
	})
	return r, err
}

func stringSliceOrEmpty(vals []string) []string {
	if vals == nil {
		return []string{}
	}
	return vals
}
