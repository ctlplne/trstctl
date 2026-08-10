// SPDX-License-Identifier: MPL-2.0

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

// FleetReissuanceHealthGate is one operator-visible health gate recorded on a
// compromised-issuer run. It is evidence metadata only; health command output,
// secrets, and credential bytes do not belong here.
type FleetReissuanceHealthGate struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// FleetReissuanceBatch records the identities processed together during a
// compromised-issuer run, with the replacement ids created for that batch.
type FleetReissuanceBatch struct {
	Index                  int      `json:"index"`
	Status                 string   `json:"status"`
	IdentityIDs            []string `json:"identity_ids"`
	ReplacementIdentityIDs []string `json:"replacement_identity_ids"`
	HealthGate             string   `json:"health_gate"`
}

// IncidentFleetReissuanceRun is the projected evidence pack for a compromised
// issuer fleet reissuance. It stores only ids, graph/evidence JSON, status, and
// rollback references; certificate/key bytes stay behind the crypto boundary.
type IncidentFleetReissuanceRun struct {
	ID                     string
	TenantID               string
	IssuerID               string
	Status                 string
	Phase                  string
	Reason                 string
	BatchSize              int
	NextBatchIndex         int
	HaltedReason           string
	Connector              string
	Target                 string
	GraphImpact            json.RawMessage
	AffectedIdentityIDs    []string
	ReplacementIdentityIDs []string
	RevokedIdentityIDs     []string
	ConnectorDeliveryIDs   []string
	Batches                []FleetReissuanceBatch
	HealthGates            []FleetReissuanceHealthGate
	FailedTargets          []string
	RollbackRefs           []string
	EvidenceBundleFormat   string
	EvidenceBundle         string
	IdempotencyKey         string
	CreatedBy              string
	CreatedAt              time.Time
	UpdatedAt              time.Time
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

// ApplyIncidentFleetReissuanceRecordedTx projects an
// incident.fleet_reissuance.recorded event. Re-emitting the same run id for
// pause/resume/rollback updates the one run row, so replay converges.
func (s *Store) ApplyIncidentFleetReissuanceRecordedTx(ctx context.Context, tx pgx.Tx, r IncidentFleetReissuanceRun) error {
	batches, err := json.Marshal(r.Batches)
	if err != nil {
		return err
	}
	healthGates, err := json.Marshal(r.HealthGates)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO incident_fleet_reissuance_runs
		        (id, tenant_id, issuer_id, status, phase, reason, batch_size,
		         next_batch_index, halted_reason,
		         connector, target, graph_impact, affected_identity_ids,
		         replacement_identity_ids, revoked_identity_ids, connector_delivery_ids,
		         batches, health_gates, failed_targets, rollback_refs,
		         evidence_bundle_format, evidence_bundle, idempotency_key, created_by,
		         created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
		         $8, $9, $10, $11, $12::jsonb, $13, $14, $15, $16,
		         $17::jsonb, $18::jsonb, $19, $20,
		         $21, $22, $23, $24, $25, $26)
		 ON CONFLICT (id) DO UPDATE
		    SET issuer_id = EXCLUDED.issuer_id,
		        status = EXCLUDED.status,
		        phase = EXCLUDED.phase,
		        reason = EXCLUDED.reason,
		        batch_size = EXCLUDED.batch_size,
		        next_batch_index = EXCLUDED.next_batch_index,
		        halted_reason = EXCLUDED.halted_reason,
		        connector = EXCLUDED.connector,
		        target = EXCLUDED.target,
		        graph_impact = EXCLUDED.graph_impact,
		        affected_identity_ids = EXCLUDED.affected_identity_ids,
		        replacement_identity_ids = EXCLUDED.replacement_identity_ids,
		        revoked_identity_ids = EXCLUDED.revoked_identity_ids,
		        connector_delivery_ids = EXCLUDED.connector_delivery_ids,
		        batches = EXCLUDED.batches,
		        health_gates = EXCLUDED.health_gates,
		        failed_targets = EXCLUDED.failed_targets,
		        rollback_refs = EXCLUDED.rollback_refs,
		        evidence_bundle_format = EXCLUDED.evidence_bundle_format,
		        evidence_bundle = EXCLUDED.evidence_bundle,
		        idempotency_key = EXCLUDED.idempotency_key,
		        created_by = EXCLUDED.created_by,
		        updated_at = EXCLUDED.updated_at`,
		r.ID, r.TenantID, r.IssuerID, r.Status, r.Phase, r.Reason, r.BatchSize,
		r.NextBatchIndex, r.HaltedReason, r.Connector, r.Target, jsonbOrEmpty(r.GraphImpact),
		stringSliceOrEmpty(r.AffectedIdentityIDs), stringSliceOrEmpty(r.ReplacementIdentityIDs),
		stringSliceOrEmpty(r.RevokedIdentityIDs), stringSliceOrEmpty(r.ConnectorDeliveryIDs),
		batches, healthGates, stringSliceOrEmpty(r.FailedTargets), stringSliceOrEmpty(r.RollbackRefs),
		r.EvidenceBundleFormat, r.EvidenceBundle, r.IdempotencyKey, r.CreatedBy,
		r.CreatedAt, r.UpdatedAt)
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

func scanIncidentFleetReissuanceRun(row pgx.Row, r *IncidentFleetReissuanceRun) error {
	var (
		graphImpact []byte
		batches     []byte
		healthGates []byte
	)
	err := row.Scan(&r.ID, &r.TenantID, &r.IssuerID, &r.Status, &r.Phase, &r.Reason,
		&r.BatchSize, &r.NextBatchIndex, &r.HaltedReason, &r.Connector, &r.Target, &graphImpact, &r.AffectedIdentityIDs,
		&r.ReplacementIdentityIDs, &r.RevokedIdentityIDs, &r.ConnectorDeliveryIDs,
		&batches, &healthGates, &r.FailedTargets, &r.RollbackRefs,
		&r.EvidenceBundleFormat, &r.EvidenceBundle, &r.IdempotencyKey, &r.CreatedBy,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return err
	}
	r.GraphImpact = append(json.RawMessage(nil), graphImpact...)
	if len(batches) > 0 {
		if err := json.Unmarshal(batches, &r.Batches); err != nil {
			return err
		}
	}
	if len(healthGates) > 0 {
		if err := json.Unmarshal(healthGates, &r.HealthGates); err != nil {
			return err
		}
	}
	if r.AffectedIdentityIDs == nil {
		r.AffectedIdentityIDs = []string{}
	}
	if r.ReplacementIdentityIDs == nil {
		r.ReplacementIdentityIDs = []string{}
	}
	if r.RevokedIdentityIDs == nil {
		r.RevokedIdentityIDs = []string{}
	}
	if r.ConnectorDeliveryIDs == nil {
		r.ConnectorDeliveryIDs = []string{}
	}
	if r.FailedTargets == nil {
		r.FailedTargets = []string{}
	}
	if r.RollbackRefs == nil {
		r.RollbackRefs = []string{}
	}
	if r.Batches == nil {
		r.Batches = []FleetReissuanceBatch{}
	}
	if r.HealthGates == nil {
		r.HealthGates = []FleetReissuanceHealthGate{}
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

// ListIncidentFleetReissuanceRunsPage returns fleet reissuance evidence for one
// tenant, optionally scoped to a compromised issuer.
func (s *Store) ListIncidentFleetReissuanceRunsPage(ctx context.Context, tenantID, issuerID, afterID string, limit int) ([]IncidentFleetReissuanceRun, error) {
	var out []IncidentFleetReissuanceRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, issuer_id::text, status, phase, reason,
			        batch_size, next_batch_index, halted_reason, connector, target, graph_impact, affected_identity_ids,
			        replacement_identity_ids, revoked_identity_ids, connector_delivery_ids,
			        batches, health_gates, failed_targets, rollback_refs,
			        evidence_bundle_format, evidence_bundle, idempotency_key, created_by,
			        created_at, updated_at
			   FROM incident_fleet_reissuance_runs
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3 = '' OR issuer_id::text = $3)
			  ORDER BY id
			  LIMIT $4`, tenantID, afterID, issuerID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r IncidentFleetReissuanceRun
			if err := scanIncidentFleetReissuanceRun(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetIncidentFleetReissuanceRun loads one fleet run in its tenant context.
func (s *Store) GetIncidentFleetReissuanceRun(ctx context.Context, tenantID, id string) (IncidentFleetReissuanceRun, error) {
	var r IncidentFleetReissuanceRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanIncidentFleetReissuanceRun(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, issuer_id::text, status, phase, reason,
			        batch_size, next_batch_index, halted_reason, connector, target, graph_impact, affected_identity_ids,
			        replacement_identity_ids, revoked_identity_ids, connector_delivery_ids,
			        batches, health_gates, failed_targets, rollback_refs,
			        evidence_bundle_format, evidence_bundle, idempotency_key, created_by,
			        created_at, updated_at
			   FROM incident_fleet_reissuance_runs
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
