// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// DynamicSecretLeaseState is the control-plane lifecycle state of a generated
// credential. Revocation delivery is tracked separately because the lease becomes
// unusable in trstctl as soon as revocation is requested, while the outbox may
// still be retrying the provider-side deletion.
type DynamicSecretLeaseState string

const (
	DynamicSecretLeasePending DynamicSecretLeaseState = "pending"
	DynamicSecretLeaseActive  DynamicSecretLeaseState = "active"
	DynamicSecretLeaseFailed  DynamicSecretLeaseState = "failed"
	DynamicSecretLeaseRevoked DynamicSecretLeaseState = "revoked"
)

// DynamicSecretRevocationStatus is the provider-side revocation outcome for a
// revoked lease.
type DynamicSecretRevocationStatus string

const (
	DynamicSecretRevocationNone      DynamicSecretRevocationStatus = "none"
	DynamicSecretRevocationPending   DynamicSecretRevocationStatus = "pending"
	DynamicSecretRevocationCompleted DynamicSecretRevocationStatus = "completed"
	DynamicSecretRevocationFailed    DynamicSecretRevocationStatus = "failed"
)

// DynamicSecretLease is the event-projected metadata for one generated
// credential. BackendRef is an opaque provider revocation handle (for example a
// database username or cloud access-key id), never the generated credential.
// The only credential-bearing field is envelope ciphertext bound to this row;
// plaintext never belongs in this record.
type DynamicSecretLease struct {
	ID             string
	TenantID       string
	TenantEpoch    string
	IdempotencyKey string
	// RequestBinding is a non-secret digest of authenticated principal +
	// canonical provider/role/TTL. It outlives the response cache so the sealed
	// credential can never be reopened for a colliding caller.
	RequestBinding string
	Provider       string
	Role           string
	BackendRef     string
	// SealedCredential is the envelope-sealed one-time provider result. It is
	// retained only while the lease is active so a crash between outbox delivery
	// and the API idempotency commit can replay the identical credential without
	// creating a second upstream principal.
	SealedCredential []byte
	// SealedPreparation is worker-created, envelope-encrypted material that makes
	// PreparedProvider retries converge on the same upstream identity. It is
	// cleared when issuance reaches any terminal state.
	SealedPreparation []byte
	// PreparationDigest remains after terminal ciphertext cleanup. It makes an
	// old prepared-event replay exact instead of silently accepting result B after
	// warm SQL had used result A.
	PreparationDigest string
	PreparedAt        *time.Time
	// CredentialDigest is the same permanent comparison receipt for the sealed
	// provider result. The plaintext never enters this row or digest input.
	CredentialDigest      string
	State                 DynamicSecretLeaseState
	IssueOutboxID         int64
	RevocationStatus      DynamicSecretRevocationStatus
	RevokeOutboxID        *int64
	LastError             string
	IssuedAt              time.Time
	ExpiresAt             time.Time
	HardExpiresAt         time.Time
	RevokedAt             *time.Time
	RevocationCompletedAt *time.Time
	UpdatedAt             time.Time
}

// ApplyDynamicSecretLeasePendingTx projects a dynsecret.lease.pending event before
// the first provider call. The tenant-unique IdempotencyKey lets a retry find and
// resume the same deterministic lease id after a process crash, instead of
// creating a second provider credential. BackendRef is deliberately empty until
// the provider reports success.
func (s *Store) ApplyDynamicSecretLeasePendingTx(ctx context.Context, tx pgx.Tx, lease DynamicSecretLease) error {
	if lease.TenantID == "" || lease.ID == "" || lease.IdempotencyKey == "" ||
		lease.Provider == "" || lease.Role == "" || lease.IssueOutboxID <= 0 ||
		lease.IssuedAt.IsZero() || lease.ExpiresAt.IsZero() {
		return errors.New("store: dynamic-secret pending lease is incomplete")
	}
	var err error
	lease.TenantEpoch, err = s.resolveDynamicSecretWriteEpochTx(ctx, tx, lease.TenantID, lease.TenantEpoch)
	if err != nil {
		return err
	}
	hardExpiresAt := lease.HardExpiresAt
	if hardExpiresAt.IsZero() {
		hardExpiresAt = lease.ExpiresAt
	}
	updatedAt := lease.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = lease.IssuedAt
	}
	preparationDigest := lease.PreparationDigest
	var preparedAt *time.Time
	if len(lease.SealedPreparation) > 0 {
		if preparationDigest == "" {
			preparationDigest = crypto.SHA256Hex(lease.SealedPreparation)
		}
		prepared := updatedAt
		preparedAt = &prepared
	}
	// The same per-command lock the issued/revoked applies take, and taken before
	// the leases table for the same reason (operations -> leases on the request
	// side, leases -> operations on the worker side must not form a cycle). It also
	// makes a concurrent identical pending apply converge on ON CONFLICT instead of
	// tripping the outbox or idempotency unique indexes (DP2-043/DP2-046 family).
	if err := lockDynamicSecretOperationTx(ctx, tx, lease.TenantID, lease.TenantEpoch, lease.IdempotencyKey); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO dynamic_secret_leases
		        (tenant_id, tenant_epoch, id, idempotency_key, request_binding, provider, role, backend_ref,
		         sealed_preparation, preparation_digest, prepared_at, sealed_credential, credential_digest,
		         state, issue_outbox_id, revocation_status, issued_at, expires_at, hard_expires_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, '', COALESCE($8::bytea, ''::bytea), $9, $10,
		         ''::bytea, '', 'pending', $11, 'none', $12, $13, $14, $15)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET id = dynamic_secret_leases.id
		  WHERE dynamic_secret_leases.tenant_epoch = EXCLUDED.tenant_epoch
		    AND dynamic_secret_leases.idempotency_key = EXCLUDED.idempotency_key
		    AND dynamic_secret_leases.request_binding = EXCLUDED.request_binding
		    AND dynamic_secret_leases.provider = EXCLUDED.provider
		    AND dynamic_secret_leases.role = EXCLUDED.role
		    AND dynamic_secret_leases.issue_outbox_id = EXCLUDED.issue_outbox_id
		    AND dynamic_secret_leases.hard_expires_at = EXCLUDED.hard_expires_at
		    AND (dynamic_secret_leases.state <> 'pending' OR
		         (dynamic_secret_leases.issued_at = EXCLUDED.issued_at
		          AND dynamic_secret_leases.expires_at = EXCLUDED.expires_at))
		    AND (EXCLUDED.preparation_digest = '' OR
		         dynamic_secret_leases.preparation_digest IN ('', EXCLUDED.preparation_digest))`,
		lease.TenantID, lease.TenantEpoch, lease.ID, lease.IdempotencyKey, lease.RequestBinding, lease.Provider, lease.Role,
		lease.SealedPreparation, preparationDigest, preparedAt, lease.IssueOutboxID,
		lease.IssuedAt, lease.ExpiresAt, hardExpiresAt, updatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: dynamic-secret pending lease differs from retained command", ErrIdempotencyConflict)
	}
	return nil
}

// ApplyDynamicSecretLeasePreparedTx persists only envelope ciphertext produced
// by the outbox worker before its first PreparedProvider mutation. Replays after
// activation cannot replace or resurrect preparation material.
func (s *Store) ApplyDynamicSecretLeasePreparedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID, provider string, sealed []byte, preparedAt time.Time) error {
	return s.ApplyDynamicSecretLeasePreparedForEpochTx(ctx, tx, tenantID, "", leaseID, provider, sealed, preparedAt)
}

func (s *Store) ApplyDynamicSecretLeasePreparedForEpochTx(ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID, provider string, sealed []byte, preparedAt time.Time) error {
	if len(sealed) == 0 {
		return fmt.Errorf("store: dynamic secret preparation ciphertext is empty")
	}
	if leaseID == "" || provider == "" || preparedAt.IsZero() {
		return errors.New("store: dynamic-secret preparation evidence is incomplete")
	}
	var err error
	tenantEpoch, err = s.resolveDynamicSecretWriteEpochTx(ctx, tx, tenantID, tenantEpoch)
	if err != nil {
		return err
	}
	var currentEpoch, currentProvider, currentDigest string
	var currentSealed []byte
	var currentPreparedAt *time.Time
	var state DynamicSecretLeaseState
	if err := tx.QueryRow(ctx, `
		SELECT tenant_epoch, provider, sealed_preparation, preparation_digest, prepared_at, state
		  FROM dynamic_secret_leases
		 WHERE tenant_id = $1 AND id = $2
		 FOR UPDATE`, tenantID, leaseID).Scan(
		&currentEpoch, &currentProvider, &currentSealed, &currentDigest, &currentPreparedAt, &state); err != nil {
		return err
	}
	digest := crypto.SHA256Hex(sealed)
	if currentEpoch != tenantEpoch || currentProvider != provider ||
		(currentDigest != "" && currentDigest != digest) ||
		(len(currentSealed) > 0 && !bytes.Equal(currentSealed, sealed)) ||
		(currentPreparedAt != nil && !sameDynamicSecretTime(*currentPreparedAt, preparedAt)) {
		return fmt.Errorf("%w: dynamic-secret preparation differs from canonical result", ErrIdempotencyConflict)
	}
	if state != DynamicSecretLeasePending &&
		(currentPreparedAt == nil || currentDigest == "" && len(currentSealed) == 0) {
		return fmt.Errorf("%w: terminal dynamic-secret preparation has no retained replay proof",
			ErrIdempotencyConflict)
	}
	if currentDigest == digest && currentPreparedAt != nil &&
		(state != DynamicSecretLeasePending || len(currentSealed) > 0) {
		return nil
	}
	_, err = tx.Exec(ctx, `
		UPDATE dynamic_secret_leases
		   SET sealed_preparation = CASE WHEN state = 'pending' THEN $4 ELSE sealed_preparation END,
		       preparation_digest = $5,
		       prepared_at = COALESCE(prepared_at, $6),
		       updated_at = CASE WHEN state = 'pending' THEN GREATEST(updated_at, $6) ELSE updated_at END
		 WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3`,
		tenantID, tenantEpoch, leaseID, sealed, digest, preparedAt)
	return err
}

// ApplyDynamicSecretLeaseIssuedTx projects a dynsecret.lease.issued event. The
// update activates the preceding pending row and stores only the envelope-sealed
// generated credential. Replaying it against an active/revoked row is a no-op. The
// idempotency key must match the pending row, so a different request can never
// claim another request's deterministic lease id. If an older caller has no
// separate hard expiry, the initial expiry becomes the hard bound.
func (s *Store) ApplyDynamicSecretLeaseIssuedTx(ctx context.Context, tx pgx.Tx, lease DynamicSecretLease) error {
	if lease.TenantID == "" || lease.ID == "" || lease.IdempotencyKey == "" ||
		lease.Provider == "" || lease.Role == "" || lease.BackendRef == "" ||
		len(lease.SealedCredential) == 0 || lease.IssuedAt.IsZero() || lease.ExpiresAt.IsZero() {
		return errors.New("store: dynamic-secret issued result is incomplete")
	}
	var err error
	lease.TenantEpoch, err = s.resolveDynamicSecretWriteEpochTx(ctx, tx, lease.TenantID, lease.TenantEpoch)
	if err != nil {
		return err
	}
	// This transaction walks leases -> operations while the request-side intent
	// transaction walks operations -> leases.  Take the shared per-command lock
	// before either table so the two orders cannot form a cycle; a 40P01 here
	// aborts a projection that has already minted an external credential, and the
	// outbox retry would then mint a second one.
	if err := lockDynamicSecretOperationTx(ctx, tx, lease.TenantID, lease.TenantEpoch, lease.IdempotencyKey); err != nil {
		return err
	}
	hardExpiresAt := lease.HardExpiresAt
	if hardExpiresAt.IsZero() {
		hardExpiresAt = lease.ExpiresAt
	}
	updatedAt := lease.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = lease.IssuedAt
	}
	current, err := loadDynamicSecretLeaseForUpdateTx(ctx, tx, lease.TenantID, lease.ID)
	if err != nil {
		return err
	}
	digest := crypto.SHA256Hex(lease.SealedCredential)
	if current.TenantEpoch != lease.TenantEpoch || current.IdempotencyKey != lease.IdempotencyKey ||
		current.RequestBinding != lease.RequestBinding || current.Provider != lease.Provider ||
		current.Role != lease.Role || !sameDynamicSecretTime(current.HardExpiresAt, hardExpiresAt) ||
		dynamicSecretTimeBefore(current.ExpiresAt, lease.ExpiresAt) {
		return fmt.Errorf("%w: dynamic-secret issued result differs from pending command", ErrIdempotencyConflict)
	}
	switch current.State {
	case DynamicSecretLeasePending:
		if !sameDynamicSecretTime(current.ExpiresAt, lease.ExpiresAt) {
			return fmt.Errorf("%w: dynamic-secret issued expiry differs from pending command", ErrIdempotencyConflict)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE dynamic_secret_leases
			   SET backend_ref = $4,
			       sealed_credential = $5,
			       credential_digest = $6,
			       sealed_preparation = ''::bytea,
			       state = 'active', issued_at = $7, expires_at = $8,
			       hard_expires_at = $9, last_error = '', updated_at = $10
			 WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3 AND state = 'pending'`,
			lease.TenantID, lease.TenantEpoch, lease.ID, lease.BackendRef,
			lease.SealedCredential, digest, lease.IssuedAt, lease.ExpiresAt,
			hardExpiresAt, updatedAt); err != nil {
			return err
		}
	case DynamicSecretLeaseActive, DynamicSecretLeaseRevoked:
		if current.BackendRef != lease.BackendRef || !sameDynamicSecretTime(current.IssuedAt, lease.IssuedAt) ||
			(current.CredentialDigest != "" && current.CredentialDigest != digest) ||
			(len(current.SealedCredential) > 0 && !bytes.Equal(current.SealedCredential, lease.SealedCredential)) {
			return fmt.Errorf("%w: dynamic-secret issued replay carries a different provider result", ErrIdempotencyConflict)
		}
		if current.CredentialDigest == "" {
			if len(current.SealedCredential) == 0 {
				return fmt.Errorf("%w: terminal dynamic-secret result has no retained replay proof",
					ErrIdempotencyConflict)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE dynamic_secret_leases
				   SET credential_digest = $4
				 WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3`,
				lease.TenantID, lease.TenantEpoch, lease.ID, digest); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%w: dynamic-secret issued result conflicts with lease state %s", ErrIdempotencyConflict, current.State)
	}
	binding := lease.RequestBinding
	if binding == "" {
		binding = "legacy-unbound"
	}
	if err := applyDynamicSecretOperationCompletedForValidatedEpochTx(
		ctx, tx, lease.TenantID, lease.TenantEpoch, "issue:"+lease.ID,
		binding, "issue", lease.ID, updatedAt,
	); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

// ApplyDynamicSecretLeaseIssuanceFailedTx projects a terminal provider creation
// failure. A stale failure replayed after activation cannot downgrade the lease.
func (s *Store) ApplyDynamicSecretLeaseIssuanceFailedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID, lastError string, failedAt time.Time) error {
	tenantEpoch, err := s.resolveDynamicSecretWriteEpochTx(ctx, tx, tenantID, "")
	if err != nil {
		return err
	}
	return s.ApplyDynamicSecretLeaseIssuanceFailedForEpochTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, lastError, failedAt)
}

// ApplyDynamicSecretLeaseIssuanceFailedForEpochTx applies a terminal failure
// only to the tenant registration named by immutable event authority. Lifecycle
// validation deliberately happens before the advisory lock or lease row lock so
// offboard keeps the global lifecycle -> command -> receiver lock order.
func (s *Store) ApplyDynamicSecretLeaseIssuanceFailedForEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, tenantEpoch, leaseID, lastError string,
	failedAt time.Time,
) error {
	if tenantID == "" || leaseID == "" || lastError == "" || failedAt.IsZero() {
		return errors.New("store: dynamic-secret issuance failure is incomplete")
	}
	if err := s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantID, tenantEpoch); err != nil {
		return err
	}
	// Same first-lock discipline as the issued projection: this transaction also
	// walks leases -> operations. The tenant lifecycle is already pinned above;
	// this plain SELECT takes no receiver row lock before the shared command lane.
	var failedIdempotencyKey string
	if err := tx.QueryRow(ctx,
		`SELECT idempotency_key
		   FROM dynamic_secret_leases
		  WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3`,
		tenantID, tenantEpoch, leaseID).Scan(&failedIdempotencyKey); err != nil {
		return err
	}
	if err := lockDynamicSecretOperationTx(
		ctx, tx, tenantID, tenantEpoch, failedIdempotencyKey,
	); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET state = CASE WHEN state = 'pending' THEN 'failed' ELSE state END,
		        sealed_credential = CASE WHEN state = 'pending' THEN ''::bytea ELSE sealed_credential END,
		        sealed_preparation = CASE WHEN state = 'pending' THEN ''::bytea ELSE sealed_preparation END,
		        last_error = CASE WHEN state = 'pending' THEN $3 ELSE last_error END,
		        updated_at = GREATEST(updated_at, $4)
		  WHERE tenant_id = $1 AND tenant_epoch = $5 AND id = $2`,
		tenantID, leaseID, lastError, failedAt, tenantEpoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	if err := applyDynamicSecretIssueOperationFailedForValidatedEpochTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, lastError, failedAt,
	); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

// ApplyDynamicSecretLeaseRenewedTx projects a dynsecret.lease.renewed event. The
// database expiry constraint rejects a renewal past HardExpiresAt, so a replay
// cannot silently widen the provider's configured maximum lease lifetime.
func (s *Store) ApplyDynamicSecretLeaseRenewedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID string, expiresAt, updatedAt time.Time) error {
	tenantEpoch, err := s.resolveDynamicSecretWriteEpochTx(ctx, tx, tenantID, "")
	if err != nil {
		return err
	}
	return s.ApplyDynamicSecretLeaseRenewedForEpochTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, expiresAt, updatedAt)
}

func (s *Store) ApplyDynamicSecretLeaseRenewedForEpochTx(ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID string, expiresAt, updatedAt time.Time) error {
	if tenantID == "" || leaseID == "" || expiresAt.IsZero() || updatedAt.IsZero() {
		return errors.New("store: dynamic-secret renewal is incomplete")
	}
	if err := s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantID, tenantEpoch); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET expires_at = CASE
		            WHEN $4 >= updated_at THEN $3
		            ELSE expires_at
		        END,
		        updated_at = GREATEST(updated_at, $4)
		  WHERE tenant_id = $1 AND tenant_epoch = $5 AND id = $2 AND state = 'active'`,
		tenantID, leaseID, expiresAt, updatedAt, tenantEpoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDynamicSecretLeaseRevocationRequestedTx projects the event that makes a
// lease unusable and records the outbox row responsible for provider deletion.
// The event and outbox enqueue are expected to share tx (AN-6). A duplicate old
// event cannot regress an already-completed revocation back to pending.
func (s *Store) ApplyDynamicSecretLeaseRevocationRequestedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID string, outboxID int64, revokedAt time.Time) error {
	tenantEpoch, err := s.resolveDynamicSecretWriteEpochTx(ctx, tx, tenantID, "")
	if err != nil {
		return err
	}
	return s.ApplyDynamicSecretLeaseRevocationRequestedForEpochTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, outboxID, revokedAt)
}

func (s *Store) ApplyDynamicSecretLeaseRevocationRequestedForEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, tenantEpoch, leaseID string,
	outboxID int64,
	revokedAt time.Time,
) error {
	if tenantID == "" || leaseID == "" || outboxID <= 0 || revokedAt.IsZero() {
		return errors.New("store: dynamic-secret revocation request is incomplete")
	}
	if err := s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantID, tenantEpoch); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET state = 'revoked',
		        sealed_credential = ''::bytea,
		        revocation_status = CASE
		            WHEN revocation_status = 'completed' THEN 'completed'
		            ELSE 'pending'
		        END,
		        revoke_outbox_id = COALESCE(revoke_outbox_id, $3),
		        last_error = CASE
		            WHEN revocation_status = 'completed' THEN last_error
		            ELSE ''
		        END,
		        revoked_at = COALESCE(revoked_at, $4),
		        updated_at = GREATEST(updated_at, $4)
		  WHERE tenant_id = $1 AND tenant_epoch = $5 AND id = $2
		    AND state IN ('active', 'revoked')`,
		tenantID, leaseID, outboxID, revokedAt, tenantEpoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDynamicSecretLeaseRevocationCompletedTx projects successful provider-side
// deletion after the outbox worker completes the external call.
func (s *Store) ApplyDynamicSecretLeaseRevocationCompletedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID string, completedAt time.Time) error {
	tenantEpoch, err := s.resolveDynamicSecretWriteEpochTx(ctx, tx, tenantID, "")
	if err != nil {
		return err
	}
	return s.ApplyDynamicSecretLeaseRevocationCompletedForEpochTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, completedAt)
}

func (s *Store) ApplyDynamicSecretLeaseRevocationCompletedForEpochTx(ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID string, completedAt time.Time) error {
	if tenantID == "" || leaseID == "" || completedAt.IsZero() {
		return errors.New("store: dynamic-secret revocation completion is incomplete")
	}
	if err := s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantID, tenantEpoch); err != nil {
		return err
	}
	var status DynamicSecretRevocationStatus
	var retainedCompletedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT revocation_status, revocation_completed_at
		  FROM dynamic_secret_leases
		 WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3 AND state = 'revoked'
		 FOR UPDATE`, tenantID, tenantEpoch, leaseID).Scan(&status, &retainedCompletedAt); err != nil {
		return err
	}
	switch status {
	case DynamicSecretRevocationCompleted:
		if retainedCompletedAt == nil || !sameDynamicSecretTime(*retainedCompletedAt, completedAt) {
			return fmt.Errorf("%w: terminal dynamic-secret revocation completion has no exact replay proof", ErrIdempotencyConflict)
		}
		return nil
	case DynamicSecretRevocationFailed:
		return fmt.Errorf("%w: dynamic-secret revocation has both completed and failed outcomes", ErrIdempotencyConflict)
	case DynamicSecretRevocationPending:
	default:
		return fmt.Errorf("%w: dynamic-secret revocation completion conflicts with status %s", ErrIdempotencyConflict, status)
	}
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET revocation_status = 'completed', last_error = '',
		        revocation_completed_at = COALESCE(revocation_completed_at, $3),
		        updated_at = GREATEST(updated_at, $3)
		  WHERE tenant_id = $1 AND tenant_epoch = $4 AND id = $2 AND state = 'revoked'`,
		tenantID, leaseID, completedAt, tenantEpoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDynamicSecretLeaseRevocationFailedTx projects a terminal outbox failure.
// Replaying a stale failure after a success cannot downgrade completed evidence.
func (s *Store) ApplyDynamicSecretLeaseRevocationFailedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID, lastError string, failedAt time.Time) error {
	tenantEpoch, err := s.resolveDynamicSecretWriteEpochTx(ctx, tx, tenantID, "")
	if err != nil {
		return err
	}
	return s.ApplyDynamicSecretLeaseRevocationFailedForEpochTx(
		ctx, tx, tenantID, tenantEpoch, leaseID, lastError, failedAt)
}

func (s *Store) ApplyDynamicSecretLeaseRevocationFailedForEpochTx(ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, leaseID, lastError string, failedAt time.Time) error {
	if tenantID == "" || leaseID == "" || lastError == "" || failedAt.IsZero() {
		return errors.New("store: dynamic-secret revocation failure is incomplete")
	}
	if err := s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantID, tenantEpoch); err != nil {
		return err
	}
	var status DynamicSecretRevocationStatus
	var currentError string
	var currentUpdatedAt time.Time
	if err := tx.QueryRow(ctx, `
		SELECT revocation_status, last_error, updated_at
		  FROM dynamic_secret_leases
		 WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3 AND state = 'revoked'
		 FOR UPDATE`, tenantID, tenantEpoch, leaseID).Scan(
		&status, &currentError, &currentUpdatedAt); err != nil {
		return err
	}
	switch status {
	case DynamicSecretRevocationFailed:
		if currentError != lastError || !sameDynamicSecretTime(currentUpdatedAt, failedAt) {
			return fmt.Errorf("%w: terminal dynamic-secret revocation failure differs from retained proof", ErrIdempotencyConflict)
		}
		return nil
	case DynamicSecretRevocationCompleted:
		return fmt.Errorf("%w: dynamic-secret revocation has both completed and failed outcomes", ErrIdempotencyConflict)
	case DynamicSecretRevocationPending:
	default:
		return fmt.Errorf("%w: dynamic-secret revocation failure conflicts with status %s", ErrIdempotencyConflict, status)
	}
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET revocation_status = 'failed',
		        last_error = $3,
		        updated_at = GREATEST(updated_at, $4)
		  WHERE tenant_id = $1 AND tenant_epoch = $5 AND id = $2
		    AND state = 'revoked'`,
		tenantID, leaseID, lastError, failedAt, tenantEpoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// #nosec G101 -- sealed_credential is a SQL column name, not a hardcoded credential (CWE-798).
const dynamicSecretLeaseAuthoritySelect = `SELECT id, tenant_id::text, tenant_epoch,
       idempotency_key, request_binding, provider, role, backend_ref,
       sealed_credential, sealed_preparation, preparation_digest, prepared_at,
       credential_digest, state, issue_outbox_id, revocation_status,
       revoke_outbox_id, last_error, issued_at, expires_at, hard_expires_at,
       revoked_at, revocation_completed_at, updated_at
  FROM dynamic_secret_leases
 WHERE tenant_id = $1`

// loadDynamicSecretLeaseForUpdateTx locks the complete retained command/result
// tuple before an issued replay decides whether it is the first exact result or
// a conflicting second provider result. Loading the permanent digests together
// with the ciphertext is what keeps replay exact after terminal cleanup removes
// the ciphertext bytes.
func loadDynamicSecretLeaseForUpdateTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, leaseID string,
) (DynamicSecretLease, error) {
	var lease DynamicSecretLease
	err := scanDynamicSecretLeaseAuthority(tx.QueryRow(ctx,
		dynamicSecretLeaseAuthoritySelect+`
		 AND id = $2
		 FOR UPDATE`, tenantID, leaseID), &lease)
	return lease, err
}

func scanDynamicSecretLeaseAuthority(row rowScanner, lease *DynamicSecretLease) error {
	return row.Scan(
		&lease.ID, &lease.TenantID, &lease.TenantEpoch,
		&lease.IdempotencyKey, &lease.RequestBinding, &lease.Provider,
		&lease.Role, &lease.BackendRef,
		&lease.SealedCredential, &lease.SealedPreparation,
		&lease.PreparationDigest, &lease.PreparedAt, &lease.CredentialDigest,
		&lease.State, &lease.IssueOutboxID, &lease.RevocationStatus,
		&lease.RevokeOutboxID, &lease.LastError,
		&lease.IssuedAt, &lease.ExpiresAt, &lease.HardExpiresAt,
		&lease.RevokedAt, &lease.RevocationCompletedAt, &lease.UpdatedAt,
	)
}

// PostgreSQL timestamptz keeps microseconds. Exact replay comparisons therefore
// discard only the sub-microsecond bits that cannot survive a database round
// trip; a difference of one retained microsecond still fails closed.
func sameDynamicSecretTime(left, right time.Time) bool {
	return canonicalDynamicSecretTime(left).Equal(canonicalDynamicSecretTime(right))
}

func dynamicSecretTimeBefore(left, right time.Time) bool {
	return canonicalDynamicSecretTime(left).Before(canonicalDynamicSecretTime(right))
}

func canonicalDynamicSecretTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

// GetDynamicSecretLease returns one lease in its tenant's RLS context.
func (s *Store) GetDynamicSecretLease(ctx context.Context, tenantID, leaseID string) (DynamicSecretLease, error) {
	var lease DynamicSecretLease
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDynamicSecretLeaseAuthority(tx.QueryRow(ctx,
			dynamicSecretLeaseAuthoritySelect+`
			 AND id = $2`,
			tenantID, leaseID), &lease)
	})
	return lease, err
}

// GetDynamicSecretLeaseByIdempotencyKey finds the durable request record a retry
// must resume before making any provider call. Store.IsNotFound recognizes the
// returned pgx.ErrNoRows when the key has never been claimed.
func (s *Store) GetDynamicSecretLeaseByIdempotencyKey(ctx context.Context, tenantID, idempotencyKey string) (DynamicSecretLease, error) {
	var lease DynamicSecretLease
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDynamicSecretLeaseAuthority(tx.QueryRow(ctx,
			dynamicSecretLeaseAuthoritySelect+`
			 AND idempotency_key = $2`,
			tenantID, idempotencyKey), &lease)
	})
	return lease, err
}

// ListDynamicSecretLeasesPage returns a bounded id-keyset page for one tenant.
// Empty provider/state filters mean all providers/states.
func (s *Store) ListDynamicSecretLeasesPage(ctx context.Context, tenantID, provider string, state DynamicSecretLeaseState, afterID string, limit int) ([]DynamicSecretLease, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: ListDynamicSecretLeasesPage requires a tenant id (AN-1)")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("store: ListDynamicSecretLeasesPage requires a positive limit")
	}
	var out []DynamicSecretLease
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, dynamicSecretLeaseAuthoritySelect+`
			 AND id > $2
			    AND ($3 = '' OR provider = $3)
			    AND ($4 = '' OR state = $4)
			  ORDER BY id
			  LIMIT $5`,
			tenantID, afterID, provider, string(state), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var lease DynamicSecretLease
			if err := scanDynamicSecretLeaseAuthority(rows, &lease); err != nil {
				return err
			}
			out = append(out, lease)
		}
		return rows.Err()
	})
	return out, err
}

// ListDueDynamicSecretLeases returns active leases whose expiry has arrived. It
// is the restart-safe input for the expiry scheduler; the caller emits revocation
// events and enqueues one outbox intent per returned lease.
func (s *Store) ListDueDynamicSecretLeases(ctx context.Context, tenantID string, now time.Time, limit int) ([]DynamicSecretLease, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: ListDueDynamicSecretLeases requires a tenant id (AN-1)")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("store: ListDueDynamicSecretLeases requires a positive limit")
	}
	var out []DynamicSecretLease
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, dynamicSecretLeaseAuthoritySelect+`
			 AND state = 'active' AND expires_at <= $2
			  ORDER BY expires_at, id
			  LIMIT $3`,
			tenantID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var lease DynamicSecretLease
			if err := scanDynamicSecretLeaseAuthority(rows, &lease); err != nil {
				return err
			}
			out = append(out, lease)
		}
		return rows.Err()
	})
	return out, err
}
