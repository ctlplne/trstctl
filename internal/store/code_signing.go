// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	CodeSigningCommandDestination = "codesign.command"
	CodeSigningCleanupDestination = "codesign.cleanup"
)

// CodeSigningOperation is the tenant-scoped read model for one durable signing
// command. SealedCommand is deployment-KEK ciphertext; plaintext identity
// assertions and digests never enter PostgreSQL or the event log.
type CodeSigningOperation struct {
	TenantID        string
	OperationID     string
	IdempotencyKey  string
	Mode            string
	RequestHash     string
	SealedCommand   []byte
	Status          string
	Response        []byte
	EphemeralHandle string
	CleanupStatus   string
	CommandOutboxID int64
	CleanupOutboxID int64
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (s *Store) CodeSigningOperationByIdempotency(ctx context.Context, tenantID, key string) (CodeSigningOperation, bool, error) {
	var op CodeSigningOperation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCodeSigningOperation(tx.QueryRow(ctx,
			`SELECT tenant_id::text, operation_id, idempotency_key, mode, request_hash,
			        sealed_command, status, response, ephemeral_handle, cleanup_status,
			        command_outbox_id, COALESCE(cleanup_outbox_id, 0), last_error,
			        created_at, updated_at
			   FROM code_signing_operations
			  WHERE tenant_id = $1 AND idempotency_key = $2`, tenantID, key), &op)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CodeSigningOperation{}, false, nil
	}
	return op, err == nil, err
}

func (s *Store) CodeSigningOperationByID(ctx context.Context, tenantID, operationID string) (CodeSigningOperation, bool, error) {
	var op CodeSigningOperation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCodeSigningOperation(tx.QueryRow(ctx,
			`SELECT tenant_id::text, operation_id, idempotency_key, mode, request_hash,
			        sealed_command, status, response, ephemeral_handle, cleanup_status,
			        command_outbox_id, COALESCE(cleanup_outbox_id, 0), last_error,
			        created_at, updated_at
			   FROM code_signing_operations
			  WHERE tenant_id = $1 AND operation_id = $2`, tenantID, operationID), &op)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CodeSigningOperation{}, false, nil
	}
	return op, err == nil, err
}

type codeSignRowScanner interface{ Scan(...any) error }

func scanCodeSigningOperation(row codeSignRowScanner, op *CodeSigningOperation) error {
	return row.Scan(
		&op.TenantID, &op.OperationID, &op.IdempotencyKey, &op.Mode,
		&op.RequestHash, &op.SealedCommand, &op.Status, &op.Response,
		&op.EphemeralHandle, &op.CleanupStatus, &op.CommandOutboxID,
		&op.CleanupOutboxID, &op.LastError, &op.CreatedAt, &op.UpdatedAt,
	)
}

// ApplyCodeSigningIntentTx projects the immutable command and its worker intent
// in one tenant transaction (AN-2/AN-6). A second event for the same
// Idempotency-Key is deliberately a no-op: the first event remains authoritative
// and the request path compares RequestHash to reject a changed replay.
func (s *Store) ApplyCodeSigningIntentTx(ctx context.Context, tx pgx.Tx, op CodeSigningOperation, commandPayload []byte) error {
	if op.TenantID == "" || op.OperationID == "" || op.IdempotencyKey == "" || op.RequestHash == "" || len(op.SealedCommand) == 0 || len(commandPayload) == 0 {
		return errors.New("store: code-signing intent is incomplete")
	}
	if op.Mode != "key" && op.Mode != "keyless" {
		return fmt.Errorf("store: unsupported code-signing mode %q", op.Mode)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"codesign-intent\x1f"+op.TenantID+"\x1f"+op.IdempotencyKey); err != nil {
		return fmt.Errorf("store: lock code-signing intent: %w", err)
	}
	var (
		existingOperation string
		existingOutboxID  int64
	)
	err := tx.QueryRow(ctx,
		`SELECT operation_id, command_outbox_id FROM code_signing_operations
		  WHERE tenant_id = $1 AND idempotency_key = $2`,
		op.TenantID, op.IdempotencyKey).Scan(&existingOperation, &existingOutboxID)
	if err == nil {
		if existingOperation != op.OperationID {
			return nil // first command remains authoritative; request path reports conflict
		}
		commandKey := "codesign.command:" + op.OperationID
		outboxID, ensureErr := ensureCodeSigningOutboxTx(ctx, tx, op.TenantID, CodeSigningCommandDestination,
			codeSigningEffectLane(CodeSigningCommandDestination, op.OperationID), commandKey, commandPayload)
		if ensureErr != nil {
			return ensureErr
		}
		if outboxID != existingOutboxID {
			return fmt.Errorf("store: code-signing operation/outbox identity mismatch")
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	commandKey := "codesign.command:" + op.OperationID
	outboxID, err := ensureCodeSigningOutboxTx(ctx, tx, op.TenantID, CodeSigningCommandDestination,
		codeSigningEffectLane(CodeSigningCommandDestination, op.OperationID), commandKey, commandPayload)
	if err != nil {
		return err
	}
	cleanupStatus := "not_required"
	_, err = tx.Exec(ctx,
		`INSERT INTO code_signing_operations
		        (tenant_id, operation_id, idempotency_key, mode, request_hash,
		         sealed_command, status, cleanup_status, command_outbox_id,
		         created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7, $8, $9, $9)
		 ON CONFLICT DO NOTHING`,
		op.TenantID, op.OperationID, op.IdempotencyKey, op.Mode, op.RequestHash,
		op.SealedCommand, cleanupStatus, outboxID, op.CreatedAt)
	return err
}

// ApplyCodeSigningCompletedTx stores the exact API response and, in the same
// projection transaction, creates the Rekor and key-cleanup intents. Thus a
// crash can observe neither a completion without its follow-up work nor follow-up
// work without the immutable completion event.
func (s *Store) ApplyCodeSigningCompletedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, operationID, requestHash string,
	response []byte,
	rekorDestination string,
	rekorPayload []byte,
	ephemeralHandle string,
	at time.Time,
) error {
	if tenantID == "" || operationID == "" || requestHash == "" || len(response) == 0 || rekorDestination == "" || len(rekorPayload) == 0 {
		return errors.New("store: code-signing completion is incomplete")
	}
	if _, err := ensureCodeSigningOutboxTx(ctx, tx, tenantID, rekorDestination,
		codeSigningEffectLane(rekorDestination, operationID), "codesign.rekor:"+operationID, rekorPayload); err != nil {
		return err
	}
	var cleanupID any
	cleanupStatus := "not_required"
	if ephemeralHandle != "" {
		body := []byte(fmt.Sprintf(`{"operation_id":%q}`, operationID))
		id, err := ensureCodeSigningOutboxTx(ctx, tx, tenantID, CodeSigningCleanupDestination,
			codeSigningEffectLane(CodeSigningCleanupDestination, operationID), "codesign.cleanup:"+operationID, body)
		if err != nil {
			return err
		}
		cleanupID = id
		cleanupStatus = "pending"
	}
	tag, err := tx.Exec(ctx,
		`UPDATE code_signing_operations
		    SET status = 'completed', response = $4, ephemeral_handle = $5,
		        cleanup_status = $6, cleanup_outbox_id = $7, last_error = '',
		        updated_at = $8
		  WHERE tenant_id = $1 AND operation_id = $2 AND request_hash = $3
		    AND status IN ('queued', 'completed')`,
		tenantID, operationID, requestHash, response, ephemeralHandle,
		cleanupStatus, cleanupID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ApplyCodeSigningFailedTx(ctx context.Context, tx pgx.Tx, tenantID, operationID, failure, ephemeralHandle string, at time.Time) error {
	if tenantID == "" || operationID == "" || failure == "" {
		return errors.New("store: code-signing failure is incomplete")
	}
	var cleanupID any
	cleanupStatus := "not_required"
	if ephemeralHandle != "" {
		body := []byte(fmt.Sprintf(`{"operation_id":%q}`, operationID))
		id, err := ensureCodeSigningOutboxTx(ctx, tx, tenantID, CodeSigningCleanupDestination,
			codeSigningEffectLane(CodeSigningCleanupDestination, operationID), "codesign.cleanup:"+operationID, body)
		if err != nil {
			return err
		}
		cleanupID = id
		cleanupStatus = "pending"
	}
	tag, err := tx.Exec(ctx,
		`UPDATE code_signing_operations
		    SET status = CASE WHEN status = 'completed' THEN status ELSE 'failed' END,
		        last_error = CASE WHEN status = 'completed' THEN last_error ELSE $3 END,
		        ephemeral_handle = CASE WHEN status = 'completed' THEN ephemeral_handle ELSE $4 END,
		        cleanup_status = CASE WHEN status = 'completed' THEN cleanup_status ELSE $5 END,
		        cleanup_outbox_id = CASE WHEN status = 'completed' THEN cleanup_outbox_id ELSE $6 END,
		        updated_at = GREATEST(updated_at, $7)
		  WHERE tenant_id = $1 AND operation_id = $2`, tenantID, operationID, failure,
		ephemeralHandle, cleanupStatus, cleanupID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ApplyCodeSigningCleanupCompletedTx(ctx context.Context, tx pgx.Tx, tenantID, operationID string, at time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE code_signing_operations
		    SET cleanup_status = 'completed', updated_at = GREATEST(updated_at, $3)
		  WHERE tenant_id = $1 AND operation_id = $2 AND mode = 'keyless'
		    AND cleanup_status IN ('pending', 'completed')`, tenantID, operationID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func codeSigningEffectLane(destination, operationID string) string {
	return destination + ":" + operationID
}

func ensureCodeSigningOutboxTx(ctx context.Context, tx pgx.Tx, tenantID, destination, effectLane, key string, payload []byte) (int64, error) {
	if tenantID == "" || destination == "" || effectLane == "" || key == "" || len(payload) == 0 {
		return 0, errors.New("store: code-signing outbox identity is incomplete")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"codesign-outbox\x1f"+tenantID+"\x1f"+key); err != nil {
		return 0, err
	}
	var id int64
	var foundDestination string
	var foundEffectLane string
	var foundPayload []byte
	err := tx.QueryRow(ctx,
		`SELECT id, destination, effect_lane, payload FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id LIMIT 1`, tenantID, key).Scan(&id, &foundDestination, &foundEffectLane, &foundPayload)
	if err == nil {
		if foundDestination != destination || (foundEffectLane != "" && foundEffectLane != effectLane) || !bytes.Equal(foundPayload, payload) {
			return 0, fmt.Errorf("store: code-signing outbox idempotency collision for %q", key)
		}
		if foundEffectLane == "" {
			if _, err := tx.Exec(ctx,
				`UPDATE outbox SET effect_lane = $3
				  WHERE tenant_id = $1 AND id = $2 AND effect_lane = ''`, tenantID, id, effectLane); err != nil {
				return 0, err
			}
		}
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	err = tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tenantID, destination, effectLane, payload, key).Scan(&id)
	return id, err
}
