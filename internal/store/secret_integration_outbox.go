// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
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
	var err error
	lease.TenantEpoch, err = s.resolveDynamicSecretWriteEpochTx(
		ctx, tx, lease.TenantID, lease.TenantEpoch)
	if err != nil {
		return err
	}
	command, err := decodeDynamicSecretIssueOutboxBinding(payload)
	if err != nil {
		return err
	}
	hardExpiresAt := lease.HardExpiresAt
	if hardExpiresAt.IsZero() {
		hardExpiresAt = lease.ExpiresAt
	}
	if command.TenantEpoch != lease.TenantEpoch || command.ID != lease.ID ||
		command.IdempotencyKey != lease.IdempotencyKey ||
		command.RequestBinding != lease.RequestBinding || command.Provider != lease.Provider ||
		command.Role != lease.Role ||
		!sameDynamicSecretTime(command.ExpiresAt, lease.ExpiresAt) ||
		!sameDynamicSecretTime(command.HardExpiresAt, hardExpiresAt) ||
		!bytes.Equal(command.SealedPreparation, lease.SealedPreparation) {
		return fmt.Errorf("%w: dynamic-secret issue outbox payload differs from lease command", ErrIdempotencyConflict)
	}
	binding := lease.RequestBinding
	if binding == "" {
		binding = "legacy-unbound"
	}
	if err := s.ApplyDynamicSecretOperationRequestedTx(ctx, tx, DynamicSecretOperation{
		TenantID: lease.TenantID, TenantEpoch: lease.TenantEpoch, OperationID: "issue:" + lease.ID,
		IdempotencyKey: lease.IdempotencyKey, RequestBinding: binding,
		Action: "issue", LeaseID: lease.ID, Response: []byte(`{}`),
		CreatedAt: lease.IssuedAt, UpdatedAt: lease.UpdatedAt,
	}); err != nil {
		return err
	}
	key := DynamicSecretIssueOutboxIdempotencyKey(lease.TenantEpoch, lease.ID)
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
	tenantEpoch, err := s.resolveDynamicSecretWriteEpochTx(ctx, tx, tenantID, "")
	if err != nil {
		return err
	}
	return s.ApplyDynamicSecretRevocationIntentForEpochTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, payload, revokedAt, false)
}

// ApplyDynamicSecretRevocationIntentForEpochTx is ApplyDynamicSecretRevocationIntentTx
// for a resolved epoch; retainCredential keeps the lease's sealed credential for
// a provider that revokes by presenting it (an OAuth access token, A239).
func (s *Store) ApplyDynamicSecretRevocationIntentForEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, tenantEpoch, leaseID string,
	payload []byte,
	revokedAt time.Time,
	retainCredential bool,
) error {
	if tenantID == "" || tenantEpoch == "" || leaseID == "" || revokedAt.IsZero() {
		return errors.New("store: dynamic-secret revocation intent is incomplete")
	}
	if err := s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantID, tenantEpoch); err != nil {
		return err
	}
	command, err := DecodeDynamicSecretRevokeOutboxBinding(payload)
	if err != nil {
		return err
	}
	var currentEpoch, provider, backendRef string
	var state DynamicSecretLeaseState
	if err := tx.QueryRow(ctx,
		`SELECT tenant_epoch, provider, backend_ref, state
		   FROM dynamic_secret_leases
		  WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3`,
		tenantID, tenantEpoch, leaseID).Scan(&currentEpoch, &provider, &backendRef, &state); err != nil {
		return fmt.Errorf("store: load dynamic-secret revoke effect lane: %w", err)
	}
	if command.TenantEpoch != tenantEpoch || currentEpoch != tenantEpoch ||
		command.LeaseID != leaseID || command.Provider != provider ||
		(command.RefSource == "" && command.BackendRef != backendRef) || command.AttemptID != "" ||
		(state != DynamicSecretLeaseActive && state != DynamicSecretLeaseRevoked) {
		return fmt.Errorf("%w: dynamic-secret revoke outbox payload differs from lease command", ErrIdempotencyConflict)
	}
	if command.RefSource == DynamicSecretRevokeFromIssuedLease {
		retainCredential = strings.HasPrefix(backendRef, "oauth:") || strings.HasPrefix(backendRef, "github-app:")
	}
	key := DynamicSecretRevokeOutboxIdempotencyKey(tenantEpoch, leaseID)
	outboxID, err := ensureDynamicSecretRevokeOutboxTx(ctx, tx, tenantID, key, command, payload)
	if err != nil {
		return err
	}
	return s.ApplyDynamicSecretLeaseRevocationRequestedForEpochTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, outboxID, revokedAt, retainCredential)
}

// ApplyDynamicSecretRevocationRetryIntentForEpochTx projects an operator's
// explicit retry after provider removal exhausted its first bounded attempt.
// The new outbox row and pending read state commit in the same transaction; the
// prior failed row and immutable failure event remain available for audit.
func (s *Store) ApplyDynamicSecretRevocationRetryIntentForEpochTx(
	ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID, attemptID string,
	previousOutboxID int64, payload []byte,
) error {
	if previousOutboxID <= 0 {
		return errors.New("store: dynamic-secret revocation retry is incomplete")
	}
	return s.applyDynamicSecretRevocationRetryTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, attemptID, previousOutboxID, "", payload)
}

// ApplyDynamicSecretRevocationRetryByAttemptForEpochTx resolves the stable
// predecessor to the live outbox row before fencing the lease update.
func (s *Store) ApplyDynamicSecretRevocationRetryByAttemptForEpochTx(
	ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID, attemptID, previousAttempt string, payload []byte,
) error {
	if previousAttempt == "" {
		return errors.New("store: dynamic-secret revocation retry has no logical predecessor")
	}
	return s.applyDynamicSecretRevocationRetryTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, attemptID, 0, previousAttempt, payload)
}

func (s *Store) applyDynamicSecretRevocationRetryTx(
	ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID, attemptID string,
	previousOutboxID int64, previousAttempt string, payload []byte,
) error {
	if tenantID == "" || tenantEpoch == "" || leaseID == "" || attemptID == "" {
		return errors.New("store: dynamic-secret revocation retry is incomplete")
	}
	if err := s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantID, tenantEpoch); err != nil {
		return err
	}
	command, err := DecodeDynamicSecretRevokeOutboxBinding(payload)
	if err != nil {
		return err
	}
	var provider, backendRef, status string
	var currentOutboxID int64
	if err := tx.QueryRow(ctx,
		`SELECT provider, backend_ref, revocation_status, revoke_outbox_id
		   FROM dynamic_secret_leases
		  WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3 AND state = 'revoked'
		  FOR UPDATE`, tenantID, tenantEpoch, leaseID).Scan(&provider, &backendRef, &status, &currentOutboxID); err != nil {
		return fmt.Errorf("store: load failed dynamic-secret revocation: %w", err)
	}
	if command.TenantEpoch != tenantEpoch || command.LeaseID != leaseID ||
		command.Provider != provider || (command.RefSource == "" && command.BackendRef != backendRef) || command.AttemptID != attemptID {
		return fmt.Errorf("%w: dynamic-secret retry payload differs from lease", ErrIdempotencyConflict)
	}
	key := DynamicSecretRevokeOutboxIdempotencyKeyForAttempt(tenantEpoch, leaseID, attemptID)
	outboxID, err := ensureDynamicSecretRevokeOutboxTx(ctx, tx, tenantID, key, command, payload)
	if err != nil {
		return err
	}
	if currentOutboxID == outboxID {
		return nil // exact event replay after its transaction already committed
	}
	if status != string(DynamicSecretRevocationFailed) {
		return fmt.Errorf("%w: dynamic-secret retry requires the exact failed predecessor", ErrIdempotencyConflict)
	}
	predecessor, fields, err := dynamicSecretRevokeOutboxRow(ctx, tx, tenantID, currentOutboxID)
	defer secret.Wipe(fields.Payload)
	if err != nil {
		return err
	}
	if predecessor.TenantEpoch != tenantEpoch || predecessor.LeaseID != leaseID || predecessor.Provider != provider ||
		(predecessor.RefSource == "" && predecessor.BackendRef != backendRef) {
		return fmt.Errorf("%w: dynamic-secret retry predecessor belongs to another lease", ErrIdempotencyConflict)
	}
	if previousOutboxID > 0 {
		// A legacy v2 event named the original physical row. A delivered
		// placeholder synthesized by rebuild cannot prove the old failed row,
		// even if a restored sequence happened to allocate the same number.
		if currentOutboxID != previousOutboxID || predecessor.RefSource != "" || fields.Status == "delivered" {
			return fmt.Errorf("%w: restore the original outbox row for the historical numeric revoke predecessor", ErrIdempotencyConflict)
		}
	} else if predecessor.logicalAttempt() != previousAttempt {
		return fmt.Errorf("%w: dynamic-secret retry predecessor attempt is mismatched", ErrIdempotencyConflict)
	}
	result, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET revocation_status = 'pending', revoke_outbox_id = $4,
		        last_error = '', revocation_completed_at = NULL, revocation_method = '', updated_at = now()
		  WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3
		    AND state = 'revoked' AND revocation_status = 'failed' AND revoke_outbox_id = $5`,
		tenantID, tenantEpoch, leaseID, outboxID, currentOutboxID)
	if err != nil {
		return fmt.Errorf("store: project dynamic-secret revocation retry: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("%w: dynamic-secret retry predecessor changed", ErrIdempotencyConflict)
	}
	return nil
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
	if job.TenantID == "" || job.TenantEpoch == "" || job.ID == "" || job.SecretName == "" || job.SecretVersion <= 0 || job.Target == "" || job.RemoteKey == "" || job.ValueDigest == "" || job.IdempotencyKey == "" || job.TargetOrder <= 0 || destination == "" || len(payload) == 0 {
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
	effectLane := "secret.sync:" + job.Target
	// Read and authenticate retained ciphertext before the job's lower-order
	// intent lock. The locked path below rechecks the complete row image before
	// consuming this proof; a worker update between the reads causes a retry.
	verifiedOutboxRows := make(map[int64]string)
	recoveryKeyHashes := make(map[int64]string)
	verifyCandidate := func(query string, args ...any) error {
		var id int64
		var rowImage string
		var retainedPayload []byte
		err := tx.QueryRow(ctx, query, args...).Scan(&id, &rowImage, &retainedPayload)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, already := verifiedOutboxRows[id]; already {
			return nil
		}
		retained, err := decodeSecretSyncOutboxBinding(retainedPayload)
		if err != nil {
			return fmt.Errorf("%w: retained secret-sync payload is invalid", ErrIdempotencyConflict)
		}
		if !bytes.Equal(retained.Sealed, proposedPayload.Sealed) {
			if operationID, recovery := recoveryPairProofOperation(ctx); recovery {
				if len(job.EventSHA256) != 64 {
					return ErrRecoveryPairProofMismatch
				}
				keyHash, err := s.RecoveryKeyStateDigestTx(ctx, tx, job.TenantID, operationID)
				if err != nil {
					return err
				}
				if err := s.ConsumeRecoveryPairProofTx(ctx, tx, RecoveryPairProof{
					TenantID: job.TenantID, OperationID: operationID, EventID: job.EventID,
					PairKind: "sync_outbox", RowID: strconv.FormatInt(id, 10),
					EventSHA256: job.EventSHA256, RowSHA256: crypto.SHA256Hex([]byte(rowImage)),
					KeyStateSHA256: keyHash,
				}); err != nil {
					return err
				}
				recoveryKeyHashes[id] = keyHash
			} else {
				if job.VerifyRewrapPair == nil {
					return fmt.Errorf("%w: secret-sync retained ciphertext differs", ErrIdempotencyConflict)
				}
				same, err := job.VerifyRewrapPair(ctx, retained.Sealed, proposedPayload.Sealed,
					[]byte(job.TenantID+"/secret-sync/"+job.Target+"/"+job.ID+"/"+job.RemoteKey))
				if err != nil || !same {
					return fmt.Errorf("%w: secret-sync retained ciphertext differs", ErrIdempotencyConflict)
				}
			}
		}
		verifiedOutboxRows[id] = rowImage
		return nil
	}
	if err := verifyCandidate(`SELECT o.id, to_jsonb(o)::text, o.payload
		FROM outbox AS o JOIN secret_sync_jobs AS j
		  ON j.tenant_id=o.tenant_id AND j.outbox_id=o.id
		WHERE j.tenant_id=$1 AND j.id=$2`, job.TenantID, job.ID); err != nil {
		return err
	}
	if err := verifyCandidate(`SELECT id, to_jsonb(o)::text, payload FROM outbox AS o
		WHERE tenant_id=$1 AND idempotency_key=$2 AND destination=$3`,
		job.TenantID, job.IdempotencyKey, destination); err != nil {
		return err
	}
	verifiedRow := func(id int64, rowImage string, retainedPayload []byte) bool {
		if before, ok := verifiedOutboxRows[id]; ok {
			return before == rowImage
		}
		// A concurrent projector can commit the identical immutable event
		// after the pre-lock read saw no row. Exact payload equality needs no
		// ciphertext pair proof; a differing copy still fails closed here.
		return bytes.Equal(retainedPayload, payload)
	}
	checkRecoveryKey := func(id int64) error {
		old, ok := recoveryKeyHashes[id]
		if !ok {
			return nil
		}
		operationID, _ := recoveryPairProofOperation(ctx)
		current, err := s.RecoveryKeyStateDigestTx(ctx, tx, job.TenantID, operationID)
		if err != nil || current != old {
			return ErrRecoveryPairProofMismatch
		}
		return nil
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
		`SELECT id, tenant_id::text, tenant_epoch, secret_name, secret_version, target,
		        remote_key, value_digest, status, outbox_id, target_order, attempts,
		        remote_version, last_error, idempotency_key, request_binding, requested_at,
		        terminal_event_id, terminal_event_type, terminal_event_sequence,
		        terminal_event_digest, terminal_event_from_event,
		        updated_at, delivered_at
		   FROM secret_sync_jobs
		  WHERE tenant_id = $1 AND id = $2`,
		job.TenantID, job.ID), &existing)
	switch {
	case err == nil:
		if !SecretSyncCommandMatches(existing, job) {
			return fmt.Errorf("%w: secret-sync job %s", ErrIdempotencyConflict, job.ID)
		}
		var existingDestination, existingKey, existingLane, existingRowImage string
		var existingPayload []byte
		var existingOrder int64
		var orderFromEvent bool
		if err := tx.QueryRow(ctx,
			`SELECT to_jsonb(o)::text, destination, payload, idempotency_key, effect_lane,
			        secret_sync_target_order, secret_sync_order_from_event
			   FROM outbox AS o
			  WHERE tenant_id = $1 AND id = $2`,
			job.TenantID, existing.OutboxID).Scan(
			&existingRowImage, &existingDestination, &existingPayload, &existingKey, &existingLane,
			&existingOrder, &orderFromEvent); err != nil {
			if errors.Is(err, pgx.ErrNoRows) &&
				(existing.Status == SecretSyncJobDelivered || existing.Status == SecretSyncJobFailed) {
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
		if existingDestination != destination || (existingLane != "" && existingLane != effectLane) || existingKey != job.IdempotencyKey || existing.TargetOrder != existingOrder || (orderFromEvent && job.TargetOrder != existingOrder) || storedPayload.ID != job.ID || storedPayload.Key != job.RemoteKey || storedPayload.Target != job.Target || storedPayload.RequestBinding != job.RequestBinding ||
			!verifiedRow(existing.OutboxID, existingRowImage, existingPayload) {
			return fmt.Errorf("%w: secret-sync job/outbox binding differs", ErrIdempotencyConflict)
		}
		if err := checkRecoveryKey(existing.OutboxID); err != nil {
			return err
		}
		if existingLane == "" {
			if _, err := tx.Exec(ctx,
				`UPDATE outbox SET effect_lane = $3 WHERE tenant_id = $1 AND id = $2 AND effect_lane = ''`,
				job.TenantID, existing.OutboxID, effectLane); err != nil {
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
		existingRowImage                  string
		existingOrder                     int64
		orderFromEvent                    bool
	)
	err = tx.QueryRow(ctx,
		`SELECT id, to_jsonb(o)::text, destination, effect_lane, idempotency_key, payload,
		        secret_sync_target_order, secret_sync_order_from_event
		   FROM outbox AS o
		  WHERE tenant_id = $1 AND idempotency_key = $2 AND destination = $3`,
		job.TenantID, job.IdempotencyKey, destination).Scan(
		&existingOutboxID, &existingRowImage, &existingDestination, &existingLane, &existingKey,
		&existingPayload, &existingOrder, &orderFromEvent)
	if err == nil {
		if err := checkRecoveryKey(existingOutboxID); err != nil {
			return err
		}
		storedPayload, decodeErr := decodeSecretSyncOutboxBinding(existingPayload)
		if decodeErr != nil || existingDestination != destination ||
			(existingLane != "" && existingLane != effectLane) ||
			existingKey != job.IdempotencyKey || storedPayload.ID != job.ID ||
			storedPayload.Key != job.RemoteKey || storedPayload.Target != job.Target ||
			storedPayload.RequestBinding != job.RequestBinding ||
			!verifiedRow(existingOutboxID, existingRowImage, existingPayload) ||
			existingOrder == 0 ||
			(orderFromEvent && (existingOrder < 0 || existingOrder != job.TargetOrder)) ||
			(!orderFromEvent && existingOrder > 0) {
			return fmt.Errorf("%w: secret-sync retained outbox %d differs from rebuilt command", ErrIdempotencyConflict, existingOutboxID)
		}
		if existingLane == "" {
			if _, err := tx.Exec(ctx,
				`UPDATE outbox SET effect_lane = $3 WHERE tenant_id = $1 AND id = $2 AND effect_lane = ''`,
				job.TenantID, existingOutboxID, effectLane); err != nil {
				return fmt.Errorf("store: restore secret-sync effect lane: %w", err)
			}
		}
		job.OutboxID = existingOutboxID
		// Migration 0153 could not recover the original event sequence from legacy
		// PostgreSQL rows, so its retained outbox value remains the stable replay
		// authority. Every post-0153 row is marked event-derived and must match the
		// immutable replayed event sequence exactly.
		if !orderFromEvent {
			job.TargetOrder = existingOrder
		}
		return s.applySecretSyncJobQueuedTx(ctx, tx, job, !orderFromEvent)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if err := tx.QueryRow(ctx,
		`INSERT INTO outbox
		        (tenant_id, destination, effect_lane, payload, idempotency_key,
		         secret_sync_target_order, secret_sync_order_from_event)
		 VALUES ($1, $2, $3, $4, $5, $6, true)
		 RETURNING id`,
		job.TenantID, destination, effectLane, payload, job.IdempotencyKey,
		job.TargetOrder).Scan(&job.OutboxID); err != nil {
		return fmt.Errorf("store: enqueue secret-sync outbox: %w", err)
	}
	return s.ApplySecretSyncJobQueuedTx(ctx, tx, job)
}

type dynamicSecretIssueOutboxBinding struct {
	TenantEpoch       string    `json:"tenant_epoch"`
	ID                string    `json:"id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	RequestBinding    string    `json:"request_binding,omitempty"`
	Provider          string    `json:"provider"`
	Role              string    `json:"role"`
	ExpiresAt         time.Time `json:"expires_at"`
	HardExpiresAt     time.Time `json:"hard_expires_at"`
	SealedPreparation []byte    `json:"sealed_preparation,omitempty"`
}

const (
	DynamicSecretRevokeFromIssuedLease = "issued_lease"
	DynamicSecretInitialRevokeAttempt  = "initial"
)

// DynamicSecretRevokeOutboxBinding identifies the issued lease used by a
// provider-removal attempt. BackendRef is present only in retained legacy rows.
type DynamicSecretRevokeOutboxBinding struct {
	TenantEpoch string `json:"tenant_epoch"`
	LeaseID     string `json:"LeaseID"`
	Provider    string `json:"Provider"`
	RefSource   string `json:"ref_source,omitempty"`
	BackendRef  string `json:"BackendRef,omitempty"`
	AttemptID   string `json:"attempt_id,omitempty"`
}

func (b DynamicSecretRevokeOutboxBinding) logicalAttempt() string {
	if b.AttemptID == "" {
		return DynamicSecretInitialRevokeAttempt
	}
	return b.AttemptID
}

type DynamicSecretRevocationOutboxRow struct {
	Destination    string
	EffectLane     string
	IdempotencyKey string
	Status         string
	Payload        []byte
}

// GetDynamicSecretRevocationOutboxRow resolves a removal attempt within its
// tenant, and verifies the stored destination and stable idempotency key.
func (s *Store) GetDynamicSecretRevocationOutboxRow(
	ctx context.Context, tenantID string, outboxID int64,
) (DynamicSecretRevokeOutboxBinding, DynamicSecretRevocationOutboxRow, error) {
	var binding DynamicSecretRevokeOutboxBinding
	var row DynamicSecretRevocationOutboxRow
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		binding, row, err = dynamicSecretRevokeOutboxRow(ctx, tx, tenantID, outboxID)
		return err
	})
	return binding, row, err
}

func dynamicSecretRevokeOutboxRow(
	ctx context.Context, tx pgx.Tx, tenantID string, outboxID int64,
) (DynamicSecretRevokeOutboxBinding, DynamicSecretRevocationOutboxRow, error) {
	var row DynamicSecretRevocationOutboxRow
	if err := tx.QueryRow(ctx, `SELECT destination, effect_lane, idempotency_key, status, payload
		FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantID, outboxID).
		Scan(&row.Destination, &row.EffectLane, &row.IdempotencyKey, &row.Status, &row.Payload); err != nil {
		return DynamicSecretRevokeOutboxBinding{}, row, fmt.Errorf("store: load dynamic-secret revoke predecessor: %w", err)
	}
	binding, err := DecodeDynamicSecretRevokeOutboxBinding(row.Payload)
	if err != nil {
		return DynamicSecretRevokeOutboxBinding{}, row, err
	}
	if row.Destination != "dynsecret.revoke" ||
		(row.EffectLane != "dynsecret.provider:"+binding.Provider && (row.EffectLane != "" || binding.RefSource != "")) ||
		row.IdempotencyKey != DynamicSecretRevokeOutboxIdempotencyKeyForAttempt(binding.TenantEpoch, binding.LeaseID, binding.AttemptID) {
		return DynamicSecretRevokeOutboxBinding{}, row, fmt.Errorf("%w: dynamic-secret revoke outbox identity is mismatched", ErrIdempotencyConflict)
	}
	return binding, row, nil
}

// WithDynamicSecretRevocationPublication serializes lease intent selection and
// publication across authenticated operation keys and control-plane replicas.
func (s *Store) WithDynamicSecretRevocationPublication(
	ctx context.Context, tenantID, leaseID string, publish func(context.Context) error,
) error {
	conn, err := s.lockSessionPool(ctx).Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	key := "dynamic-secret-revoke:" + tenantID + ":" + leaseID
	var held bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key).Scan(&held); err != nil {
		return err
	}
	if !held {
		return ErrResourceAdmissionBusy
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := conn.Exec(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key); err != nil {
			_ = conn.Conn().Close(cleanup)
		}
	}()
	return publish(ctx)
}

// GuardDynamicSecretRevocationProjectionTx tracks the current revocation
// projection within the lease's registration. An application path may
// project several events before the ordinary stream tail reaches them.
func (s *Store) GuardDynamicSecretRevocationProjectionTx(
	ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID string, sequence uint64,
) (bool, error) {
	if sequence == 0 {
		return false, nil
	}
	var current uint64
	if err := tx.QueryRow(ctx, `SELECT revocation_event_sequence FROM dynamic_secret_leases
		WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3 FOR UPDATE`,
		tenantID, tenantEpoch, leaseID).Scan(&current); err != nil {
		return false, err
	}
	if sequence <= current {
		return sequence < current, nil
	}
	_, err := tx.Exec(ctx, `UPDATE dynamic_secret_leases SET revocation_event_sequence = $4
		WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3`, tenantID, tenantEpoch, leaseID, sequence)
	return false, err
}

// RequireDynamicSecretRevocationAttemptTx leaves the lease locked until the
// terminal projector commits. A retained result from a previous attempt cannot
// move its replacement out of pending even when the request and lease match.
func (s *Store) RequireDynamicSecretRevocationAttemptTx(
	ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID, attemptID string,
) error {
	var status DynamicSecretRevocationStatus
	var provider, reference string
	var outboxID *int64
	if err := tx.QueryRow(ctx, `SELECT revocation_status, provider, backend_ref, revoke_outbox_id
		FROM dynamic_secret_leases
		WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3 AND state = 'revoked'
		FOR UPDATE`, tenantID, tenantEpoch, leaseID).Scan(&status, &provider, &reference, &outboxID); err != nil {
		return err
	}
	if status != DynamicSecretRevocationPending {
		return nil // The terminal projector still requires the exact settled result.
	}
	if outboxID == nil {
		return fmt.Errorf("%w: pending dynamic-secret revocation has no outbox authority", ErrIdempotencyConflict)
	}
	binding, row, err := dynamicSecretRevokeOutboxRow(ctx, tx, tenantID, *outboxID)
	defer secret.Wipe(row.Payload)
	if err != nil {
		return err
	}
	if binding.TenantEpoch != tenantEpoch || binding.LeaseID != leaseID || binding.Provider != provider ||
		binding.AttemptID != attemptID || binding.RefSource == "" && binding.BackendRef != reference {
		return fmt.Errorf("%w: dynamic-secret outcome differs from the pending attempt", ErrIdempotencyConflict)
	}
	return nil
}

func ensureDynamicSecretRevokeOutboxTx(
	ctx context.Context, tx pgx.Tx, tenantID, key string,
	command DynamicSecretRevokeOutboxBinding, legacyPayload []byte,
) (int64, error) {
	if command.RefSource != "" {
		legacyPayload = nil
	}
	command.RefSource = DynamicSecretRevokeFromIssuedLease
	command.BackendRef = ""
	payload, err := json.Marshal(command)
	if err != nil {
		return 0, err
	}
	return ensureSecretIntegrationOutboxEncodingTx(ctx, tx, tenantID,
		"dynsecret.revoke", "dynsecret.provider:"+command.Provider, key, payload, legacyPayload, nil)
}

func DynamicSecretIssueOutboxIdempotencyKey(tenantEpoch, leaseID string) string {
	return "dynsecret.issue:" + tenantEpoch + ":" + leaseID
}

func DynamicSecretRevokeOutboxIdempotencyKey(tenantEpoch, leaseID string) string {
	return "dynsecret.revoke:" + tenantEpoch + ":" + leaseID
}

func DynamicSecretRevokeOutboxIdempotencyKeyForAttempt(tenantEpoch, leaseID, attemptID string) string {
	if attemptID == "" {
		return DynamicSecretRevokeOutboxIdempotencyKey(tenantEpoch, leaseID)
	}
	return "dynsecret.revoke.retry:" + tenantEpoch + ":" + leaseID + ":" + attemptID
}

func decodeDynamicSecretIssueOutboxBinding(payload []byte) (dynamicSecretIssueOutboxBinding, error) {
	var binding dynamicSecretIssueOutboxBinding
	if err := json.Unmarshal(payload, &binding); err != nil {
		return dynamicSecretIssueOutboxBinding{}, fmt.Errorf("store: decode dynamic-secret issue outbox payload: %w", err)
	}
	if binding.TenantEpoch == "" || binding.ID == "" || binding.IdempotencyKey == "" ||
		binding.Provider == "" || binding.Role == "" || binding.ExpiresAt.IsZero() ||
		binding.HardExpiresAt.IsZero() {
		return dynamicSecretIssueOutboxBinding{}, errors.New("store: dynamic-secret issue outbox payload is incomplete")
	}
	return binding, nil
}

func DecodeDynamicSecretRevokeOutboxBinding(payload []byte) (DynamicSecretRevokeOutboxBinding, error) {
	var binding DynamicSecretRevokeOutboxBinding
	if err := json.Unmarshal(payload, &binding); err != nil {
		return DynamicSecretRevokeOutboxBinding{}, errors.New("store: dynamic-secret revoke outbox payload is invalid")
	}
	if binding.TenantEpoch == "" || binding.LeaseID == "" || binding.Provider == "" {
		return DynamicSecretRevokeOutboxBinding{}, errors.New("store: dynamic-secret revoke outbox payload is incomplete")
	}
	canonical, err := json.Marshal(binding)
	defer secret.Wipe(canonical)
	legacy := binding.RefSource == "" && binding.BackendRef != ""
	fromLease := binding.RefSource == DynamicSecretRevokeFromIssuedLease && binding.BackendRef == ""
	exact := bytes.Equal(payload, canonical)
	if err == nil && legacy && !exact {
		// Older closed objects also used the sorted map encoding. Re-encode
		// only the known fields, so duplicates or extra fields still fail.
		var fields map[string]json.RawMessage
		if json.Unmarshal(canonical, &fields) == nil {
			sorted, sortedErr := json.Marshal(fields)
			exact = sortedErr == nil && bytes.Equal(payload, sorted)
			secret.Wipe(sorted)
			for _, value := range fields {
				secret.Wipe(value)
			}
		}
	}
	if err != nil || !exact || !legacy && !fromLease {
		return DynamicSecretRevokeOutboxBinding{}, errors.New("store: dynamic-secret revoke outbox reference source is invalid")
	}
	return binding, nil
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
	return a.TenantID == b.TenantID && a.TenantEpoch == b.TenantEpoch && a.ID == b.ID &&
		a.SecretName == b.SecretName && a.SecretVersion == b.SecretVersion &&
		a.Target == b.Target && a.RemoteKey == b.RemoteKey &&
		a.ValueDigest == b.ValueDigest && a.IdempotencyKey == b.IdempotencyKey &&
		a.RequestBinding == b.RequestBinding
}

func ensureSecretIntegrationOutboxTx(ctx context.Context, tx pgx.Tx, tenantID, destination, effectLane, key string, payload []byte) (int64, error) {
	return ensureSecretIntegrationOutboxAtTx(ctx, tx, tenantID, destination, effectLane, key, payload, nil)
}
func ensureSecretIntegrationOutboxAtTx(ctx context.Context, tx pgx.Tx, tenantID, destination, effectLane, key string, payload []byte, notBefore *time.Time) (int64, error) {
	return ensureSecretIntegrationOutboxEncodingTx(ctx, tx, tenantID, destination, effectLane, key, payload, nil, notBefore)
}

// A compatible legacy encoding is accepted only at the exact existing
// outbox identity. New rows always use payload and the replay watermark.
func ensureSecretIntegrationOutboxEncodingTx(
	ctx context.Context, tx pgx.Tx, tenantID, destination, effectLane, key string,
	payload, legacyPayload []byte, notBefore *time.Time,
) (int64, error) {
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
	// A237L4-L3: a rebuild re-projecting an event the deployment projected
	// before queues no second effect, but its caller keeps the row's id. A
	// row still retained is reused below; one the sweep reclaimed after
	// delivery is re-created as delivered, so the dispatcher never runs it
	// and the sweep reclaims it again.
	status, deliveredAt := replayedEffectStatus(ctx)
	var id int64
	err := tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key,next_attempt_at, status, delivered_at)
		 SELECT $1, $2, $3, $4, $5,COALESCE($6::timestamptz,now()), $7, $8
		 WHERE NOT EXISTS (
		     SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $5
		 )
		 RETURNING id`,
		tenantID, destination, effectLane, payload, key, notBefore, status, deliveredAt).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("store: enqueue secret integration outbox: %w", err)
	}
	var existingDestination, existingLane string
	var existingPayload []byte
	defer func() { secret.Wipe(existingPayload) }()
	if err := tx.QueryRow(ctx,
		`SELECT id, destination, payload, effect_lane
		   FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id
		  LIMIT 1`, tenantID, key).Scan(&id, &existingDestination, &existingPayload, &existingLane); err != nil {
		return 0, fmt.Errorf("store: load secret integration outbox: %w", err)
	}
	compatiblePayload := bytes.Equal(existingPayload, payload) || len(legacyPayload) != 0 && bytes.Equal(existingPayload, legacyPayload)
	if existingDestination != destination || (existingLane != "" && existingLane != effectLane) || !compatiblePayload {
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
