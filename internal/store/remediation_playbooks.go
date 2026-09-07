// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	RequestBinding      string
	InitialHTTPStatus   int
	InitialResponse     json.RawMessage
	TerminalReason      string
	CreatedBy           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ApplyRemediationPlaybookRunRecordedTx projects a remediation.playbook_run.recorded
// event. Re-emitting the same run id converges on one evidence row, so replay and
// idempotent request handling cannot duplicate a remediation.
func (s *Store) ApplyRemediationPlaybookRunRecordedTx(ctx context.Context, tx pgx.Tx, r RemediationPlaybookRun) error {
	if err := lockUpsertArbiterTx(ctx, tx, "remediation_playbook_runs", r.TenantID, r.ID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO remediation_playbook_runs
		        (id, tenant_id, playbook_id, target_identity_id, inventory_id,
		         status, phase, action, reason, connector, target, outbox_id,
		         connector_delivery_id, scope_delta, evidence_refs, rollback_refs,
		         idempotency_key, request_binding, initial_http_status,
		         initial_response, terminal_reason, created_by, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5,
		         $6, $7, $8, $9, $10, $11, $12,
		         $13, $14::jsonb, $15, $16,
		         $17, $18, $19, COALESCE($20, ''::bytea), $21, $22, $23, $24)
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
		        request_binding = EXCLUDED.request_binding,
		        initial_http_status = EXCLUDED.initial_http_status,
		        initial_response = EXCLUDED.initial_response,
		        terminal_reason = EXCLUDED.terminal_reason,
		        created_by = EXCLUDED.created_by,
		        updated_at = EXCLUDED.updated_at`,
		r.ID, r.TenantID, r.PlaybookID, r.TargetIdentityID, r.InventoryID,
		r.Status, r.Phase, r.Action, r.Reason, r.Connector, r.Target, r.OutboxID,
		r.ConnectorDeliveryID, jsonbOrEmpty(r.ScopeDelta),
		stringSliceOrEmpty(r.EvidenceRefs), stringSliceOrEmpty(r.RollbackRefs),
		r.IdempotencyKey, r.RequestBinding, r.InitialHTTPStatus, []byte(r.InitialResponse),
		r.TerminalReason, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	return err
}

func scanRemediationPlaybookRun(row pgx.Row, r *RemediationPlaybookRun) error {
	var (
		outboxID        sql.NullInt64
		deliveryID      sql.NullString
		scopeDelta      []byte
		initialResponse []byte
	)
	err := row.Scan(&r.ID, &r.TenantID, &r.PlaybookID, &r.TargetIdentityID, &r.InventoryID,
		&r.Status, &r.Phase, &r.Action, &r.Reason, &r.Connector, &r.Target, &outboxID,
		&deliveryID, &scopeDelta, &r.EvidenceRefs, &r.RollbackRefs,
		&r.IdempotencyKey, &r.RequestBinding, &r.InitialHTTPStatus, &initialResponse,
		&r.TerminalReason, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
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
	r.InitialResponse = append(json.RawMessage(nil), initialResponse...)
	if r.EvidenceRefs == nil {
		r.EvidenceRefs = []string{}
	}
	if r.RollbackRefs == nil {
		r.RollbackRefs = []string{}
	}
	return nil
}

// GetRemediationPlaybookRunByIdempotencyKey loads the durable right-size
// operation authority for one raw request key. Legacy playbook rows have no
// request binding and are deliberately excluded: they cannot safely authorize a
// replay once the generic API response recorder has been collected.
func (s *Store) GetRemediationPlaybookRunByIdempotencyKey(ctx context.Context, tenantID, idempotencyKey string) (RemediationPlaybookRun, error) {
	var r RemediationPlaybookRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanRemediationPlaybookRun(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, playbook_id, target_identity_id,
			        inventory_id, status, phase, action, reason, connector, target,
			        outbox_id, connector_delivery_id::text, scope_delta,
			        evidence_refs, rollback_refs, idempotency_key, request_binding,
			        initial_http_status, initial_response, terminal_reason, created_by,
			        created_at, updated_at
			   FROM remediation_playbook_runs
			  WHERE tenant_id = $1 AND idempotency_key = $2
			    AND action = 'right_size' AND request_binding <> ''`,
			tenantID, idempotencyKey), &r)
	})
	return r, err
}

// ApplyConnectorRightSizeRequestedTx projects the immutable command, its queued
// delivery receipt, and the external-call intent in one tenant transaction. The
// run row is the post-recorder-GC idempotency authority. A live duplicate is a
// no-op and cannot regress a terminal operation; rebuild gets the same outbox and
// receipt identities from the event payload.
func (s *Store) ApplyConnectorRightSizeRequestedTx(
	ctx context.Context,
	tx pgx.Tx,
	r RemediationPlaybookRun,
	receipt ConnectorDeliveryReceipt,
	destination, outboxKey string,
	payload []byte,
) error {
	if r.TenantID == "" || r.ID == "" || r.Action != "right_size" || r.IdempotencyKey == "" ||
		r.RequestBinding == "" || r.InitialHTTPStatus == 0 || len(r.InitialResponse) == 0 ||
		receipt.ID == "" || destination == "" || outboxKey == "" || len(payload) == 0 {
		return fmt.Errorf("store: connector right-size operation is incomplete")
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"connector-right-size-operation\x1f"+r.TenantID+"\x1f"+r.IdempotencyKey); err != nil {
		return fmt.Errorf("store: lock connector right-size operation: %w", err)
	}

	var existing RemediationPlaybookRun
	err := scanRemediationPlaybookRun(tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, playbook_id, target_identity_id,
		        inventory_id, status, phase, action, reason, connector, target,
		        outbox_id, connector_delivery_id::text, scope_delta,
		        evidence_refs, rollback_refs, idempotency_key, request_binding,
		        initial_http_status, initial_response, terminal_reason, created_by,
		        created_at, updated_at
		   FROM remediation_playbook_runs
		  WHERE tenant_id = $1 AND idempotency_key = $2
		    AND action = 'right_size' AND request_binding <> ''`,
		r.TenantID, r.IdempotencyKey), &existing)
	if err == nil {
		if existing.ID != r.ID || existing.RequestBinding != r.RequestBinding ||
			existing.InitialHTTPStatus != r.InitialHTTPStatus ||
			!bytes.Equal(existing.InitialResponse, r.InitialResponse) ||
			existing.ConnectorDeliveryID == nil || *existing.ConnectorDeliveryID != receipt.ID {
			return fmt.Errorf("%w: connector right-size key belongs to another command", ErrIdempotencyConflict)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	effectLane := destination + ":" + r.Connector + ":" + r.Target
	outboxID, err := ensureConnectorRightSizeOutboxTx(ctx, tx, r.TenantID, destination, effectLane, outboxKey, payload)
	if err != nil {
		return err
	}
	r.OutboxID = &outboxID
	receipt.TenantID = r.TenantID
	receipt.OutboxID = &outboxID
	if err := s.ApplyConnectorDeliveryRecordedTx(ctx, tx, receipt); err != nil {
		return err
	}
	return s.ApplyRemediationPlaybookRunRecordedTx(ctx, tx, r)
}

func ensureConnectorRightSizeOutboxTx(ctx context.Context, tx pgx.Tx, tenantID, destination, effectLane, key string, payload []byte) (int64, error) {
	var (
		id                  int64
		existingDestination string
		existingEffectLane  string
		existingPayload     []byte
	)
	err := tx.QueryRow(ctx,
		`SELECT id, destination, COALESCE(NULLIF(effect_lane, ''), destination), payload
		   FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id LIMIT 1`, tenantID, key).Scan(&id, &existingDestination, &existingEffectLane, &existingPayload)
	if err == nil {
		if existingDestination != destination || existingEffectLane != effectLane || !bytes.Equal(existingPayload, payload) {
			return 0, fmt.Errorf("%w: connector right-size outbox command differs", ErrIdempotencyConflict)
		}
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tenantID, destination, payload, key, effectLane).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// ApplyConnectorRightSizeTerminalTx advances one durable operation exactly once.
// Same-terminal event replay converges; a stale opposite terminal event cannot
// overwrite the first authoritative outcome.
func (s *Store) ApplyConnectorRightSizeTerminalTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, runID, deliveryID string,
	outboxID int64,
	status, phase, terminalReason string,
	at time.Time,
) error {
	if tenantID == "" || runID == "" || deliveryID == "" || outboxID == 0 ||
		(status != "succeeded" && status != "failed") || phase == "" || terminalReason == "" {
		return fmt.Errorf("store: connector right-size terminal state is incomplete")
	}
	tag, err := tx.Exec(ctx,
		`UPDATE remediation_playbook_runs
		    SET status = $5, phase = $6, terminal_reason = $7,
		        updated_at = GREATEST(updated_at, $8)
		  WHERE tenant_id = $1 AND id = $2 AND action = 'right_size'
		    AND connector_delivery_id = $3 AND outbox_id = $4
		    AND request_binding <> ''
		    AND (status = 'queued' OR
		         (status = $5 AND phase = $6 AND terminal_reason = $7))`,
		tenantID, runID, deliveryID, outboxID, status, phase, terminalReason, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var foundStatus string
		if err := tx.QueryRow(ctx,
			`SELECT status FROM remediation_playbook_runs
			  WHERE tenant_id = $1 AND id = $2 AND action = 'right_size'`,
			tenantID, runID).Scan(&foundStatus); err != nil {
			return err
		}
		return fmt.Errorf("%w: connector right-size operation is already %s", ErrIdempotencyConflict, foundStatus)
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
			        evidence_refs, rollback_refs, idempotency_key, request_binding,
			        initial_http_status, initial_response, terminal_reason, created_by,
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
			        evidence_refs, rollback_refs, idempotency_key, request_binding,
			        initial_http_status, initial_response, terminal_reason, created_by,
			        created_at, updated_at
			   FROM remediation_playbook_runs
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &r)
	})
	return r, err
}
