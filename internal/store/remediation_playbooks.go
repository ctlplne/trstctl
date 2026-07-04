// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// RemediationPlaybookRun is the projected evidence pack for one automated
// remediation playbook run. It stores identifiers, deltas, rollback references,
// and outbox/connector evidence only; credential, key, and provider secret bytes
// never belong in this row.
type RemediationPlaybookRun struct {
	ID                  string
	TenantID            string
	PlaybookID          string
	TargetIdentityID    string
	InventoryID         string
	Status              string
	Phase               string
	Action              string
	Reason              string
	Connector           string
	Target              string
	OutboxID            *int64
	ConnectorDeliveryID *string
	ScopeDelta          json.RawMessage
	EvidenceRefs        []string
	RollbackRefs        []string
	IdempotencyKey      string
	CreatedBy           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ApplyRemediationPlaybookRunRecordedTx projects a remediation.playbook_run.recorded
// event. Re-emitting the same run id converges on one evidence row, so replay and
// idempotent request handling cannot duplicate a remediation.
func (s *Store) ApplyRemediationPlaybookRunRecordedTx(ctx context.Context, tx pgx.Tx, r RemediationPlaybookRun) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO remediation_playbook_runs
		        (id, tenant_id, playbook_id, target_identity_id, inventory_id,
		         status, phase, action, reason, connector, target, outbox_id,
		         connector_delivery_id, scope_delta, evidence_refs, rollback_refs,
		         idempotency_key, created_by, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5,
		         $6, $7, $8, $9, $10, $11, $12,
		         $13, $14::jsonb, $15, $16,
		         $17, $18, $19, $20)
		 ON CONFLICT (id) DO UPDATE
		    SET playbook_id = EXCLUDED.playbook_id,
		        target_identity_id = EXCLUDED.target_identity_id,
		        inventory_id = EXCLUDED.inventory_id,
		        status = EXCLUDED.status,
		        phase = EXCLUDED.phase,
		        action = EXCLUDED.action,
		        reason = EXCLUDED.reason,
		        connector = EXCLUDED.connector,
		        target = EXCLUDED.target,
		        outbox_id = EXCLUDED.outbox_id,
		        connector_delivery_id = EXCLUDED.connector_delivery_id,
		        scope_delta = EXCLUDED.scope_delta,
		        evidence_refs = EXCLUDED.evidence_refs,
		        rollback_refs = EXCLUDED.rollback_refs,
		        idempotency_key = EXCLUDED.idempotency_key,
		        created_by = EXCLUDED.created_by,
		        updated_at = EXCLUDED.updated_at`,
		r.ID, r.TenantID, r.PlaybookID, r.TargetIdentityID, r.InventoryID,
		r.Status, r.Phase, r.Action, r.Reason, r.Connector, r.Target, r.OutboxID,
		r.ConnectorDeliveryID, jsonbOrEmpty(r.ScopeDelta),
		stringSliceOrEmpty(r.EvidenceRefs), stringSliceOrEmpty(r.RollbackRefs),
		r.IdempotencyKey, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	return err
}

func scanRemediationPlaybookRun(row pgx.Row, r *RemediationPlaybookRun) error {
	var (
		outboxID   sql.NullInt64
		deliveryID sql.NullString
		scopeDelta []byte
	)
	err := row.Scan(&r.ID, &r.TenantID, &r.PlaybookID, &r.TargetIdentityID, &r.InventoryID,
		&r.Status, &r.Phase, &r.Action, &r.Reason, &r.Connector, &r.Target, &outboxID,
		&deliveryID, &scopeDelta, &r.EvidenceRefs, &r.RollbackRefs,
		&r.IdempotencyKey, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return err
	}
	if outboxID.Valid {
		r.OutboxID = &outboxID.Int64
	}
	if deliveryID.Valid {
		r.ConnectorDeliveryID = &deliveryID.String
	}
	r.ScopeDelta = append(json.RawMessage(nil), scopeDelta...)
	if r.EvidenceRefs == nil {
		r.EvidenceRefs = []string{}
	}
	if r.RollbackRefs == nil {
		r.RollbackRefs = []string{}
	}
	return nil
}

// ListRemediationPlaybookRunsPage returns served playbook run evidence for one
// tenant, optionally scoped to a playbook id.
func (s *Store) ListRemediationPlaybookRunsPage(ctx context.Context, tenantID, playbookID, afterID string, limit int) ([]RemediationPlaybookRun, error) {
	var out []RemediationPlaybookRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, playbook_id, target_identity_id,
			        inventory_id, status, phase, action, reason, connector, target,
			        outbox_id, connector_delivery_id::text, scope_delta,
			        evidence_refs, rollback_refs, idempotency_key, created_by,
			        created_at, updated_at
			   FROM remediation_playbook_runs
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3 = '' OR playbook_id = $3)
			  ORDER BY id
			  LIMIT $4`, tenantID, afterID, playbookID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r RemediationPlaybookRun
			if err := scanRemediationPlaybookRun(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetRemediationPlaybookRun loads one playbook run in its tenant context.
func (s *Store) GetRemediationPlaybookRun(ctx context.Context, tenantID, id string) (RemediationPlaybookRun, error) {
	var r RemediationPlaybookRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanRemediationPlaybookRun(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, playbook_id, target_identity_id,
			        inventory_id, status, phase, action, reason, connector, target,
			        outbox_id, connector_delivery_id::text, scope_delta,
			        evidence_refs, rollback_refs, idempotency_key, created_by,
			        created_at, updated_at
			   FROM remediation_playbook_runs
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &r)
	})
	return r, err
}
