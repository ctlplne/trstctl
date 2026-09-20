// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

const (
	// TenantKeyDomainSealDestination is an internal, zero-egress command. The
	// normal bounded outbox dispatcher owns it so an API request never waits for
	// the cross-replica seal fence.
	TenantKeyDomainSealDestination = "tenantseal.seal"
	TenantKeyDomainSealEffectLane  = "tenantseal.seal"
)

// TenantKeyDomainSealCommand is public control metadata only. It contains no
// wrapper path, key bytes, ciphertext, or mutation result. The worker uses the
// raw idempotency key plus its non-secret request digest only to prove that the
// accepted response was durably cached before making tenant crypto unavailable.
type TenantKeyDomainSealCommand struct {
	OperationID    string `json:"operation_id"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestBinding string `json:"request_binding"`
}

// TenantKeyDomainSealOutboxKey is the stable receiver key for one exact seal
// operation. It deliberately does not reuse the caller's raw Idempotency-Key in
// the shared outbox namespace.
func TenantKeyDomainSealOutboxKey(operationID string) string {
	return TenantKeyDomainSealDestination + ":" + operationID
}

// EnsureTenantKeyDomainSealOutboxTx derives the bounded-worker command from the
// immutable seal-request event in the same RLS transaction as its projection.
// Exact event replay repairs a missing derived row and rejects any command drift.
func (s *Store) EnsureTenantKeyDomainSealOutboxTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, operationID, idempotencyKey, requestBinding string,
) error {
	if s == nil || tx == nil || strings.TrimSpace(tenantID) == "" ||
		strings.TrimSpace(operationID) == "" || strings.TrimSpace(idempotencyKey) == "" ||
		strings.TrimSpace(requestBinding) == "" {
		return fmt.Errorf("store: tenant key-domain seal outbox requires tenant, operation, idempotency key, and request binding")
	}
	payload, err := json.Marshal(TenantKeyDomainSealCommand{
		OperationID: operationID, IdempotencyKey: idempotencyKey,
		RequestBinding: requestBinding,
	})
	if err != nil {
		return fmt.Errorf("store: encode tenant key-domain seal command: %w", err)
	}
	outboxKey := TenantKeyDomainSealOutboxKey(operationID)
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"tenant-key-domain-seal-outbox\x1f"+tenantID+"\x1f"+operationID); err != nil {
		return fmt.Errorf("store: lock tenant key-domain seal outbox: %w", err)
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 SELECT $1, $2, $3, $4, $5
		 WHERE NOT EXISTS (
		     SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $5
		 )`,
		tenantID, TenantKeyDomainSealDestination, TenantKeyDomainSealEffectLane,
		payload, outboxKey)
	if err != nil {
		return fmt.Errorf("store: enqueue tenant key-domain seal: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	var destination, effectLane string
	var existingPayload []byte
	if err := tx.QueryRow(ctx,
		`SELECT destination, COALESCE(NULLIF(effect_lane, ''), destination), payload
		   FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id
		  LIMIT 1`,
		tenantID, outboxKey).Scan(&destination, &effectLane, &existingPayload); err != nil {
		return fmt.Errorf("store: load tenant key-domain seal outbox replay: %w", err)
	}
	if destination != TenantKeyDomainSealDestination ||
		effectLane != TenantKeyDomainSealEffectLane || !bytes.Equal(existingPayload, payload) {
		return fmt.Errorf("%w: tenant key-domain seal outbox command differs", ErrIdempotencyConflict)
	}
	return nil
}
