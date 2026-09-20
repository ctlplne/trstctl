// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type ManagedKeyOperation struct {
	TenantID, OperationID, Provider, Action, KeyID, Algorithm, RequestBinding string
	Status, ResultKeyID, ResultState, LastError                               string
	PublicDER                                                                 []byte
	OutboxID                                                                  int64
	CreatedAt, UpdatedAt                                                      time.Time
}

type ManagedKey struct {
	TenantID, Provider, KeyID, Algorithm, State string
	Version                                     int
	PublicDER                                   []byte
	CreatedAt, UpdatedAt                        time.Time
}

const managedKeyOutboxDestination = "managedkey.command"

// ManagedKeyEffectLane returns the receiver identity that owns a managed-key
// side effect. Generate has no current key yet, so its durable operation ID is
// the receiver identity. Rotate/revoke/zeroize all serialize on the current key
// so one unhealthy key cannot open the circuit for every key at the provider.
func ManagedKeyEffectLane(provider, keyID, operationID string) string {
	effectID := keyID
	if effectID == "" {
		effectID = operationID
	}
	return managedKeyOutboxDestination + ":" + provider + ":" + effectID
}

// ApplyManagedKeyIntentTx recreates the deterministic outbox command while
// projecting the requested event. The state row and external-call intent share
// one tenant transaction (AN-6), including during event-log replay.
func (s *Store) ApplyManagedKeyIntentTx(ctx context.Context, tx pgx.Tx, op ManagedKeyOperation, payload []byte) error {
	if op.TenantID == "" || op.OperationID == "" || op.Provider == "" || op.Action == "" || op.Algorithm == "" || op.RequestBinding == "" || len(payload) == 0 {
		return fmt.Errorf("store: managed-key intent is incomplete")
	}
	// The request path and the continuous projection tail can observe the same
	// event concurrently. Serialize this exact tenant/operation before the
	// check-and-insert so both cannot create separate provider commands. The lock
	// is transaction-scoped and PostgreSQL-local; no datastore is added.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"managed-key-intent\x1f"+op.TenantID+"\x1f"+op.OperationID); err != nil {
		return fmt.Errorf("store: lock managed-key intent: %w", err)
	}
	effectLane := ManagedKeyEffectLane(op.Provider, op.KeyID, op.OperationID)
	var outboxID int64
	err := tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 SELECT $1, $2, $3, $4, $5
		 WHERE NOT EXISTS (
		     SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $5
		 )
		 RETURNING id`,
		op.TenantID, managedKeyOutboxDestination, effectLane, payload, op.OperationID).Scan(&outboxID)
	if errors.Is(err, pgx.ErrNoRows) {
		var (
			existingDestination string
			existingEffectLane  string
			existingPayload     []byte
		)
		err = tx.QueryRow(ctx,
			`SELECT id, destination, effect_lane, payload FROM outbox
			  WHERE tenant_id = $1 AND idempotency_key = $2
			  ORDER BY id LIMIT 1`, op.TenantID, op.OperationID).Scan(&outboxID, &existingDestination, &existingEffectLane, &existingPayload)
		if err == nil {
			if existingDestination != managedKeyOutboxDestination || (existingEffectLane != "" && existingEffectLane != effectLane) || !bytes.Equal(existingPayload, payload) {
				return pgx.ErrNoRows
			}
			// Rows written before effect lanes shipped are healed during event
			// replay. They must not stay collapsed onto the destination-wide
			// fallback circuit.
			if existingEffectLane == "" {
				if _, updateErr := tx.Exec(ctx,
					`UPDATE outbox SET effect_lane = $3
					  WHERE tenant_id = $1 AND id = $2 AND effect_lane = ''`,
					op.TenantID, outboxID, effectLane); updateErr != nil {
					return fmt.Errorf("store: heal managed-key effect lane: %w", updateErr)
				}
			}
		}
	}
	if err != nil {
		return fmt.Errorf("store: enqueue managed-key command: %w", err)
	}
	op.OutboxID = outboxID
	tag, err := tx.Exec(ctx,
		`INSERT INTO managed_key_operations
		        (tenant_id, operation_id, provider, action, key_id, algorithm, request_binding,
		         status, outbox_id, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', $8, $9, $9)
		 ON CONFLICT (tenant_id, operation_id) DO UPDATE
		    SET operation_id = managed_key_operations.operation_id
		  WHERE managed_key_operations.provider = EXCLUDED.provider
		    AND managed_key_operations.action = EXCLUDED.action
		    AND managed_key_operations.key_id = EXCLUDED.key_id
		    AND managed_key_operations.algorithm = EXCLUDED.algorithm
		    AND managed_key_operations.request_binding = EXCLUDED.request_binding`,
		op.TenantID, op.OperationID, op.Provider, op.Action, op.KeyID, op.Algorithm, op.RequestBinding, op.OutboxID, op.CreatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ApplyManagedKeyCompletedTx(ctx context.Context, tx pgx.Tx, op ManagedKeyOperation) error {
	if op.TenantID == "" || op.OperationID == "" || op.Provider == "" || op.Action == "" || op.ResultKeyID == "" || op.ResultState == "" || op.Algorithm == "" || op.RequestBinding == "" {
		return fmt.Errorf("store: managed-key completion is incomplete")
	}
	tag, err := tx.Exec(ctx,
		`UPDATE managed_key_operations
		    SET status = 'completed', result_key_id = $5, public_der = $6,
		        result_state = $7, last_error = '', updated_at = $8
		  WHERE tenant_id = $1 AND operation_id = $2 AND provider = $3
		    AND action = $4 AND key_id = $9 AND algorithm = $10
		    AND request_binding = $11 AND status IN ('queued', 'completed')`,
		op.TenantID, op.OperationID, op.Provider, op.Action, op.ResultKeyID,
		op.PublicDER, op.ResultState, op.UpdatedAt, op.KeyID, op.Algorithm, op.RequestBinding)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	switch op.Action {
	case "generate":
		return s.upsertManagedKeyTx(ctx, tx, ManagedKey{
			TenantID: op.TenantID, Provider: op.Provider, KeyID: op.ResultKeyID,
			Algorithm: op.Algorithm, Version: 1, State: op.ResultState,
			PublicDER: op.PublicDER, CreatedAt: op.UpdatedAt, UpdatedAt: op.UpdatedAt,
		})
	case "rotate":
		var version int
		if err := tx.QueryRow(ctx,
			`SELECT version FROM managed_keys
			  WHERE tenant_id = $1 AND provider = $2 AND key_id = $3`,
			op.TenantID, op.Provider, op.KeyID).Scan(&version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE managed_keys SET state = 'superseded', updated_at = $4
			  WHERE tenant_id = $1 AND provider = $2 AND key_id = $3`,
			op.TenantID, op.Provider, op.KeyID, op.UpdatedAt); err != nil {
			return err
		}
		return s.upsertManagedKeyTx(ctx, tx, ManagedKey{
			TenantID: op.TenantID, Provider: op.Provider, KeyID: op.ResultKeyID,
			Algorithm: op.Algorithm, Version: version + 1, State: op.ResultState,
			PublicDER: op.PublicDER, CreatedAt: op.UpdatedAt, UpdatedAt: op.UpdatedAt,
		})
	case "revoke", "zeroize":
		tag, err := tx.Exec(ctx,
			`UPDATE managed_keys
			    SET state = $4, public_der = $5, updated_at = $6
			  WHERE tenant_id = $1 AND provider = $2 AND key_id = $3`,
			op.TenantID, op.Provider, op.ResultKeyID, op.ResultState, op.PublicDER, op.UpdatedAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	default:
		return fmt.Errorf("store: unsupported managed-key action %q", op.Action)
	}
}

func (s *Store) upsertManagedKeyTx(ctx context.Context, tx pgx.Tx, key ManagedKey) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO managed_keys
		        (tenant_id, provider, key_id, algorithm, version, state, public_der, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, provider, key_id) DO UPDATE
		    SET algorithm = EXCLUDED.algorithm, version = EXCLUDED.version,
		        state = EXCLUDED.state, public_der = EXCLUDED.public_der,
		        updated_at = GREATEST(managed_keys.updated_at, EXCLUDED.updated_at)`,
		key.TenantID, key.Provider, key.KeyID, key.Algorithm, key.Version,
		key.State, key.PublicDER, key.CreatedAt, key.UpdatedAt)
	return err
}

func (s *Store) ApplyManagedKeyFailedTx(ctx context.Context, tx pgx.Tx, tenantID, operationID, requestBinding, failure string, failedAt time.Time) error {
	if tenantID == "" || operationID == "" || requestBinding == "" || failure == "" {
		return fmt.Errorf("store: managed-key failure is incomplete")
	}
	tag, err := tx.Exec(ctx,
		`UPDATE managed_key_operations
		    SET status = CASE WHEN status = 'completed' THEN status ELSE 'failed' END,
		        last_error = CASE WHEN status = 'completed' THEN last_error ELSE $4 END,
		        updated_at = GREATEST(updated_at, $5)
		  WHERE tenant_id = $1 AND operation_id = $2 AND request_binding = $3`,
		tenantID, operationID, requestBinding, failure, failedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) GetManagedKeyOperation(ctx context.Context, tenantID, operationID string) (ManagedKeyOperation, error) {
	var op ManagedKeyOperation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id, operation_id, provider, action, key_id, algorithm, request_binding,
			        status, result_key_id, public_der, result_state, outbox_id,
			        last_error, created_at, updated_at
			   FROM managed_key_operations
			  WHERE tenant_id = $1 AND operation_id = $2`,
			tenantID, operationID).Scan(
			&op.TenantID, &op.OperationID, &op.Provider, &op.Action, &op.KeyID, &op.Algorithm, &op.RequestBinding,
			&op.Status, &op.ResultKeyID, &op.PublicDER, &op.ResultState, &op.OutboxID,
			&op.LastError, &op.CreatedAt, &op.UpdatedAt)
	})
	return op, err
}

func (s *Store) GetManagedKey(ctx context.Context, tenantID, provider, keyID string) (ManagedKey, error) {
	var key ManagedKey
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		key, err = s.ManagedKeyApprovalTargetTx(ctx, tx, tenantID, provider, keyID, false)
		return err
	})
	return key, err
}

// ManagedKeyApprovalTargetTx reads the exact event-projected target generation.
// The command path requests a row lock so the state/version approved by reviewers
// cannot change between authority validation and requested-event projection.
func (s *Store) ManagedKeyApprovalTargetTx(ctx context.Context, tx pgx.Tx, tenantID, provider, keyID string, lock bool) (ManagedKey, error) {
	locking := ""
	if lock {
		locking = " FOR UPDATE"
	}
	var key ManagedKey
	err := tx.QueryRow(ctx,
		`SELECT tenant_id, provider, key_id, algorithm, version, state,
		        public_der, created_at, updated_at
		   FROM managed_keys
		  WHERE tenant_id = $1 AND provider = $2 AND key_id = $3`+locking,
		tenantID, provider, keyID).Scan(
		&key.TenantID, &key.Provider, &key.KeyID, &key.Algorithm, &key.Version,
		&key.State, &key.PublicDER, &key.CreatedAt, &key.UpdatedAt)
	if err != nil {
		return ManagedKey{}, err
	}
	if key.Version < 0 {
		return ManagedKey{}, fmt.Errorf("store: managed-key version is negative")
	}
	return key, nil
}

// ValidateManagedKeyApprovalCommandTx joins the generic one-shot authority to
// managed-key-only intent fields not repeated in OperationApprovalUse. The digest
// still identifies the whole immutable request; this comparison proves the event
// carries the same reviewer-visible key name and non-secret command evidence.
// Readiness and consumption are deliberately left to the generic approval APIs.
func (s *Store) ValidateManagedKeyApprovalCommandTx(ctx context.Context, tx pgx.Tx, tenantID string, use OperationApprovalUse, resourceName string, evidenceRefs []string) (OperationApprovalRequest, error) {
	request, err := s.getOperationApprovalTx(ctx, tx, tenantID, use.RequestID, true)
	if err != nil {
		return OperationApprovalRequest{}, err
	}
	if err := validateOperationApprovalUseBinding(request, use); err != nil {
		return OperationApprovalRequest{}, err
	}
	if request.ResourceName != resourceName || !sameManagedKeyApprovalEvidence(request.EvidenceRefs, evidenceRefs) {
		return OperationApprovalRequest{}, ErrApprovalDrifted
	}
	return request, nil
}

func sameManagedKeyApprovalEvidence(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
