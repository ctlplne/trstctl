// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApplyDynamicSecretIssueIntentTx atomically reserves the pending lease and the
// provider-side issuance command. The event projector calls this while rebuilding
// too, so an append-before-project crash recreates the same deterministic outbox
// intent instead of leaving a pending lease with no worker action.
func (s *Store) ApplyDynamicSecretIssueIntentTx(
	ctx context.Context,
	tx pgx.Tx,
	lease DynamicSecretLease,
	payload []byte,
) error {
	binding := lease.RequestBinding
	if binding == "" {
		binding = "legacy-unbound"
	}
	if err := s.ApplyDynamicSecretOperationRequestedTx(ctx, tx, DynamicSecretOperation{
		TenantID: lease.TenantID, OperationID: "issue:" + lease.ID,
		IdempotencyKey: lease.IdempotencyKey, RequestBinding: binding,
		Action: "issue", LeaseID: lease.ID, Response: []byte(`{}`),
		CreatedAt: lease.IssuedAt, UpdatedAt: lease.UpdatedAt,
	}); err != nil {
		return err
	}
	key := "dynsecret.issue:" + lease.ID
	outboxID, err := ensureSecretIntegrationOutboxTx(ctx, tx, lease.TenantID, "dynsecret.issue", "dynsecret.provider:"+lease.Provider, key, payload)
	if err != nil {
		return err
	}
	lease.IssueOutboxID = outboxID
	return s.ApplyDynamicSecretLeasePendingTx(ctx, tx, lease)
}

// ApplyDynamicSecretRevocationIntentTx projects a revocation-requested event and
// recreates its deterministic outbox intent in the same transaction. Replaying
// the event after an append/commit crash therefore heals a missing external call
// instead of rebuilding a revoked lease with no provider deletion queued.
func (s *Store) ApplyDynamicSecretRevocationIntentTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, leaseID string,
	payload []byte,
	revokedAt time.Time,
) error {
	key := "dynsecret.revoke:" + leaseID
	var provider string
	if err := tx.QueryRow(ctx,
		`SELECT provider FROM dynamic_secret_leases WHERE tenant_id = $1 AND id = $2`,
		tenantID, leaseID).Scan(&provider); err != nil {
		return fmt.Errorf("store: load dynamic-secret revoke effect lane: %w", err)
	}
	outboxID, err := ensureSecretIntegrationOutboxTx(ctx, tx, tenantID, "dynsecret.revoke", "dynsecret.provider:"+provider, key, payload)
	if err != nil {
		return err
	}
	return s.ApplyDynamicSecretLeaseRevocationRequestedTx(ctx, tx, tenantID, leaseID, outboxID, revokedAt)
}

// ApplySecretSyncIntentTx projects a queued sync job and recreates its sealed
// outbox payload atomically. The event contains ciphertext only; plaintext never
// enters either lifecycle table or the event stream.
func (s *Store) ApplySecretSyncIntentTx(
	ctx context.Context,
	tx pgx.Tx,
	job SecretSyncJob,
	destination string,
	payload []byte,
) error {
	if job.TenantID == "" || job.ID == "" || job.SecretName == "" || job.SecretVersion <= 0 || job.Target == "" || job.RemoteKey == "" || job.ValueDigest == "" || job.IdempotencyKey == "" || destination == "" || len(payload) == 0 {
		return errors.New("store: secret-sync intent is incomplete")
	}
	if destination != "secret.sync."+job.Target {
		return fmt.Errorf("%w: secret-sync destination does not match target", ErrIdempotencyConflict)
	}
	proposedPayload, err := decodeSecretSyncOutboxBinding(payload)
	if err != nil {
		return err
	}
	if proposedPayload.ID != job.ID || proposedPayload.Key != job.RemoteKey || proposedPayload.Target != job.Target || proposedPayload.RequestBinding != job.RequestBinding {
		return fmt.Errorf("%w: secret-sync payload does not match job command", ErrIdempotencyConflict)
	}

	// The job id is derived from tenant + raw Idempotency-Key and therefore stays
	// stable even when a colliding retry changes target (and thus outbox key).
	// Lock it before looking at either table so two changed commands cannot each
	// create one half of the job/outbox pair under READ COMMITTED.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"secret-sync-intent\x1f"+job.TenantID+"\x1f"+job.ID); err != nil {
		return fmt.Errorf("store: lock secret-sync intent: %w", err)
	}

	var existing SecretSyncJob
	err = scanSecretSyncJob(tx.QueryRow(ctx,
		`SELECT id, tenant_id::text, secret_name, secret_version, target,
		        remote_key, value_digest, status, outbox_id, attempts,
		        remote_version, last_error, idempotency_key, request_binding, requested_at,
		        updated_at, delivered_at
		   FROM secret_sync_jobs
		  WHERE tenant_id = $1 AND id = $2`,
		job.TenantID, job.ID), &existing)
	switch {
	case err == nil:
		if !SecretSyncCommandMatches(existing, job) {
			return fmt.Errorf("%w: secret-sync job %s", ErrIdempotencyConflict, job.ID)
		}
		var existingDestination, existingKey, existingLane string
		var existingPayload []byte
		if err := tx.QueryRow(ctx,
			`SELECT destination, payload, idempotency_key, effect_lane
			   FROM outbox
			  WHERE tenant_id = $1 AND id = $2`,
			job.TenantID, existing.OutboxID).Scan(&existingDestination, &existingPayload, &existingKey, &existingLane); err != nil {
			if errors.Is(err, pgx.ErrNoRows) && existing.Status == SecretSyncJobDelivered {
				return nil
			}
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: secret-sync job has no retained outbox", ErrIdempotencyConflict)
			}
			return fmt.Errorf("store: secret-sync job/outbox disagreement: %w", err)
		}
		storedPayload, err := decodeSecretSyncOutboxBinding(existingPayload)
		if err != nil {
			return fmt.Errorf("store: secret-sync stored outbox payload: %w", err)
		}
		if existingDestination != destination || (existingLane != "" && existingLane != "secret.sync:"+job.Target) || existingKey != job.IdempotencyKey || storedPayload.ID != job.ID || storedPayload.Key != job.RemoteKey || storedPayload.Target != job.Target || storedPayload.RequestBinding != job.RequestBinding {
			return fmt.Errorf("%w: secret-sync job/outbox binding differs", ErrIdempotencyConflict)
		}
		if existingLane == "" {
			if _, err := tx.Exec(ctx,
				`UPDATE outbox SET effect_lane = $3 WHERE tenant_id = $1 AND id = $2 AND effect_lane = ''`,
				job.TenantID, existing.OutboxID, "secret.sync:"+job.Target); err != nil {
				return fmt.Errorf("store: backfill secret-sync effect lane: %w", err)
			}
		}
		return nil
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}

	// A full event-log rebuild truncates the projected job table but deliberately
	// retains the delivery outbox. Reattach only when every immutable command
	// field matches; a cross-subsystem/key collision still fails closed.
	var (
		existingOutboxID                  int64
		existingDestination, existingLane string
		existingKey                       string
		existingPayload                   []byte
	)
	err = tx.QueryRow(ctx,
		`SELECT id, destination, effect_lane, idempotency_key, payload
		   FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id
		  LIMIT 1`, job.TenantID, job.IdempotencyKey).Scan(
		&existingOutboxID, &existingDestination, &existingLane, &existingKey, &existingPayload)
	if err == nil {
		storedPayload, decodeErr := decodeSecretSyncOutboxBinding(existingPayload)
		if decodeErr != nil || existingDestination != destination ||
			(existingLane != "" && existingLane != "secret.sync:"+job.Target) ||
			existingKey != job.IdempotencyKey || storedPayload.ID != job.ID ||
			storedPayload.Key != job.RemoteKey || storedPayload.Target != job.Target ||
			storedPayload.RequestBinding != job.RequestBinding ||
			!bytes.Equal(storedPayload.Sealed, proposedPayload.Sealed) {
			return fmt.Errorf("%w: secret-sync retained outbox %d differs from rebuilt command", ErrIdempotencyConflict, existingOutboxID)
		}
		if existingLane == "" {
			if _, err := tx.Exec(ctx,
				`UPDATE outbox SET effect_lane = $3 WHERE tenant_id = $1 AND id = $2 AND effect_lane = ''`,
				job.TenantID, existingOutboxID, "secret.sync:"+job.Target); err != nil {
				return fmt.Errorf("store: restore secret-sync effect lane: %w", err)
			}
		}
		job.OutboxID = existingOutboxID
		return s.ApplySecretSyncJobQueuedTx(ctx, tx, job)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if err := tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		job.TenantID, destination, "secret.sync:"+job.Target, payload, job.IdempotencyKey).Scan(&job.OutboxID); err != nil {
		return fmt.Errorf("store: enqueue secret-sync outbox: %w", err)
	}
	return s.ApplySecretSyncJobQueuedTx(ctx, tx, job)
}

type secretSyncOutboxBinding struct {
	ID             string `json:"id"`
	Key            string `json:"key"`
	Target         string `json:"target"`
	RequestBinding string `json:"request_binding,omitempty"`
	Sealed         []byte `json:"sealed"`
}

func decodeSecretSyncOutboxBinding(payload []byte) (secretSyncOutboxBinding, error) {
	var binding secretSyncOutboxBinding
	if err := json.Unmarshal(payload, &binding); err != nil {
		return secretSyncOutboxBinding{}, fmt.Errorf("store: decode secret-sync outbox payload: %w", err)
	}
	if binding.ID == "" || binding.Key == "" || binding.Target == "" || len(binding.Sealed) == 0 {
		return secretSyncOutboxBinding{}, errors.New("store: secret-sync outbox payload is incomplete")
	}
	return binding, nil
}

func SecretSyncCommandMatches(a, b SecretSyncJob) bool {
	return a.TenantID == b.TenantID && a.ID == b.ID &&
		a.SecretName == b.SecretName && a.SecretVersion == b.SecretVersion &&
		a.Target == b.Target && a.RemoteKey == b.RemoteKey &&
		a.ValueDigest == b.ValueDigest && a.IdempotencyKey == b.IdempotencyKey &&
		a.RequestBinding == b.RequestBinding
}

func ensureSecretIntegrationOutboxTx(ctx context.Context, tx pgx.Tx, tenantID, destination, effectLane, key string, payload []byte) (int64, error) {
	if tenantID == "" || destination == "" || effectLane == "" || key == "" || len(payload) == 0 {
		return 0, fmt.Errorf("store: secret integration outbox intent is incomplete")
	}
	// Under READ COMMITTED, two event projectors can both observe an absent row
	// before either commits. Lock the exact tenant/key pair for this transaction so
	// replay and the live tail share one durable outbox identity (AN-1/AN-6).
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"secret-integration-outbox\x1f"+tenantID+"\x1f"+key); err != nil {
		return 0, fmt.Errorf("store: lock secret integration outbox: %w", err)
	}
	var id int64
	err := tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 SELECT $1, $2, $3, $4, $5
		 WHERE NOT EXISTS (
		     SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $5
		 )
		 RETURNING id`,
		tenantID, destination, effectLane, payload, key).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("store: enqueue secret integration outbox: %w", err)
	}
	var existingDestination, existingLane string
	var existingPayload []byte
	if err := tx.QueryRow(ctx,
		`SELECT id, destination, payload, effect_lane
		   FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id
		  LIMIT 1`, tenantID, key).Scan(&id, &existingDestination, &existingPayload, &existingLane); err != nil {
		return 0, fmt.Errorf("store: load secret integration outbox: %w", err)
	}
	if existingDestination != destination || (existingLane != "" && existingLane != effectLane) || !bytes.Equal(existingPayload, payload) {
		return 0, fmt.Errorf("%w: secret integration outbox destination or payload differs", ErrIdempotencyConflict)
	}
	if existingLane == "" {
		if _, err := tx.Exec(ctx,
			`UPDATE outbox SET effect_lane = $3 WHERE tenant_id = $1 AND id = $2 AND effect_lane = ''`,
			tenantID, id, effectLane); err != nil {
			return 0, fmt.Errorf("store: backfill secret integration effect lane: %w", err)
		}
	}
	return id, nil
}
