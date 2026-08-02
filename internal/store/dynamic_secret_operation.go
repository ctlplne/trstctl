// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	DynamicSecretOperationPending   = "pending"
	DynamicSecretOperationCompleted = "completed"
	DynamicSecretOperationFailed    = "failed"
)

// DynamicSecretOperation is the durable AN-5 identity of one authenticated
// issue, renew, or revoke command. Response contains public lease metadata only;
// issued credential bytes remain envelope-sealed on DynamicSecretLease.
type DynamicSecretOperation struct {
	TenantID       string
	OperationID    string
	IdempotencyKey string
	RequestBinding string
	Action         string
	LeaseID        string
	Response       []byte
	Status         string
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// lockDynamicSecretOperationTx serializes every transaction that writes the
// dynamic_secret_operations / dynamic_secret_leases pair for one authenticated
// command.  The request-side intent projection walks operations -> leases while
// the worker-side result projection walks leases -> operations; taking this lock
// as the FIRST statement of both is what stops that ABBA order from deadlocking
// (SQLSTATE 40P01) and aborting a post-provider projection that has already
// minted an external credential.  Under READ COMMITTED an ON CONFLICT DO UPDATE
// locks the conflicting row even when its update is a semantic no-op, so both
// walks really do take both row locks.
//
// INVARIANT: every writer of that table pair takes this lock first, before it
// touches either table.  ApplySecretSyncIntentTx documents the same discipline
// for the sync job/outbox pair.
func lockDynamicSecretOperationTx(ctx context.Context, tx pgx.Tx, tenantID, idempotencyKey string) error {
	if tenantID == "" || idempotencyKey == "" {
		return fmt.Errorf("store: dynamic-secret operation lock identity is incomplete")
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"dynamic-secret-operation\x1f"+tenantID+"\x1f"+idempotencyKey); err != nil {
		return fmt.Errorf("store: lock dynamic-secret operation: %w", err)
	}
	return nil
}

// ApplyDynamicSecretOperationRequestedTx claims the raw Idempotency-Key in a
// tenant-wide namespace. The no-op conflict update succeeds only for the exact
// same authenticated command and never regresses a terminal operation.
func (s *Store) ApplyDynamicSecretOperationRequestedTx(ctx context.Context, tx pgx.Tx, op DynamicSecretOperation) error {
	if op.TenantID == "" || op.OperationID == "" || op.IdempotencyKey == "" || op.RequestBinding == "" || op.LeaseID == "" || (op.Action != "issue" && op.Action != "renew" && op.Action != "revoke") {
		return fmt.Errorf("store: dynamic-secret operation is incomplete")
	}
	if len(op.Response) == 0 {
		op.Response = []byte(`{}`)
	}
	var response map[string]any
	if err := json.Unmarshal(op.Response, &response); err != nil || response == nil {
		return fmt.Errorf("store: dynamic-secret operation response must be a JSON object")
	}
	if op.CreatedAt.IsZero() {
		op.CreatedAt = op.UpdatedAt
	}
	if op.UpdatedAt.IsZero() {
		op.UpdatedAt = op.CreatedAt
	}
	if err := lockDynamicSecretOperationTx(ctx, tx, op.TenantID, op.IdempotencyKey); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO dynamic_secret_operations
		        (tenant_id, operation_id, idempotency_key, request_binding, action,
		         lease_id, response, status, last_error, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'pending', '', $8, $9)
		 ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
		    SET operation_id = dynamic_secret_operations.operation_id
		  WHERE dynamic_secret_operations.operation_id = EXCLUDED.operation_id
		    AND dynamic_secret_operations.request_binding = EXCLUDED.request_binding
		    AND dynamic_secret_operations.action = EXCLUDED.action
		    AND dynamic_secret_operations.lease_id = EXCLUDED.lease_id
		    AND dynamic_secret_operations.response = EXCLUDED.response`,
		op.TenantID, op.OperationID, op.IdempotencyKey, op.RequestBinding, op.Action,
		op.LeaseID, op.Response, op.CreatedAt, op.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: dynamic-secret idempotency key already binds another command", ErrIdempotencyConflict)
	}
	return nil
}

func (s *Store) ApplyDynamicSecretOperationCompletedTx(ctx context.Context, tx pgx.Tx, tenantID, operationID, requestBinding, action, leaseID string, completedAt time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_operations
		    SET status = 'completed', last_error = '', updated_at = GREATEST(updated_at, $6)
		  WHERE tenant_id = $1 AND operation_id = $2 AND request_binding = $3
		    AND action = $4 AND lease_id = $5 AND status IN ('pending', 'completed')`,
		tenantID, operationID, requestBinding, action, leaseID, completedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDynamicSecretIssueOperationFailedTx makes only the issue command for the
// named lease terminal. A stale failure replay cannot overwrite completion.
func (s *Store) ApplyDynamicSecretIssueOperationFailedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID, lastError string, failedAt time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_operations
		    SET status = CASE WHEN status = 'completed' THEN status ELSE 'failed' END,
		        last_error = CASE WHEN status = 'completed' THEN last_error ELSE $3 END,
		        updated_at = GREATEST(updated_at, $4)
		  WHERE tenant_id = $1 AND lease_id = $2 AND action = 'issue'`,
		tenantID, leaseID, lastError, failedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) GetDynamicSecretOperationByIdempotencyKey(ctx context.Context, tenantID, idempotencyKey string) (DynamicSecretOperation, error) {
	var op DynamicSecretOperation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDynamicSecretOperation(tx.QueryRow(ctx,
			`SELECT tenant_id::text, operation_id, idempotency_key, request_binding,
			        action, lease_id, response, status, last_error, created_at, updated_at
			   FROM dynamic_secret_operations
			  WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantID, idempotencyKey), &op)
	})
	return op, err
}

func (s *Store) GetDynamicSecretOperation(ctx context.Context, tenantID, operationID string) (DynamicSecretOperation, error) {
	var op DynamicSecretOperation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDynamicSecretOperation(tx.QueryRow(ctx,
			`SELECT tenant_id::text, operation_id, idempotency_key, request_binding,
			        action, lease_id, response, status, last_error, created_at, updated_at
			   FROM dynamic_secret_operations
			  WHERE tenant_id = $1 AND operation_id = $2`,
			tenantID, operationID), &op)
	})
	return op, err
}

func scanDynamicSecretOperation(row rowScanner, op *DynamicSecretOperation) error {
	return row.Scan(
		&op.TenantID, &op.OperationID, &op.IdempotencyKey, &op.RequestBinding,
		&op.Action, &op.LeaseID, &op.Response, &op.Status, &op.LastError,
		&op.CreatedAt, &op.UpdatedAt,
	)
}
