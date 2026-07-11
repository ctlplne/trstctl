// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
	State             DynamicSecretLeaseState
	IssueOutboxID     int64
	RevocationStatus  DynamicSecretRevocationStatus
	RevokeOutboxID    *int64
	LastError         string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	HardExpiresAt     time.Time
	RevokedAt         *time.Time
	UpdatedAt         time.Time
}

// ApplyDynamicSecretLeasePendingTx projects a dynsecret.lease.pending event before
// the first provider call. The tenant-unique IdempotencyKey lets a retry find and
// resume the same deterministic lease id after a process crash, instead of
// creating a second provider credential. BackendRef is deliberately empty until
// the provider reports success.
func (s *Store) ApplyDynamicSecretLeasePendingTx(ctx context.Context, tx pgx.Tx, lease DynamicSecretLease) error {
	hardExpiresAt := lease.HardExpiresAt
	if hardExpiresAt.IsZero() {
		hardExpiresAt = lease.ExpiresAt
	}
	updatedAt := lease.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = lease.IssuedAt
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO dynamic_secret_leases
		        (tenant_id, id, idempotency_key, request_binding, provider, role, backend_ref,
		         sealed_preparation, sealed_credential, state, issue_outbox_id, revocation_status,
		         issued_at, expires_at, hard_expires_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, '', COALESCE($7::bytea, ''::bytea), ''::bytea, 'pending', $8, 'none', $9, $10, $11, $12)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET id = dynamic_secret_leases.id
		  WHERE dynamic_secret_leases.idempotency_key = EXCLUDED.idempotency_key
		    AND dynamic_secret_leases.request_binding = EXCLUDED.request_binding
		    AND dynamic_secret_leases.provider = EXCLUDED.provider
		    AND dynamic_secret_leases.role = EXCLUDED.role`,
		lease.TenantID, lease.ID, lease.IdempotencyKey, lease.RequestBinding, lease.Provider, lease.Role, lease.SealedPreparation,
		lease.IssueOutboxID, lease.IssuedAt, lease.ExpiresAt, hardExpiresAt, updatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDynamicSecretLeasePreparedTx persists only envelope ciphertext produced
// by the outbox worker before its first PreparedProvider mutation. Replays after
// activation cannot replace or resurrect preparation material.
func (s *Store) ApplyDynamicSecretLeasePreparedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID, provider string, sealed []byte, preparedAt time.Time) error {
	if len(sealed) == 0 {
		return fmt.Errorf("store: dynamic secret preparation ciphertext is empty")
	}
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET sealed_preparation = CASE
		            WHEN state = 'pending' AND octet_length(sealed_preparation) = 0 THEN $4
		            ELSE sealed_preparation
		        END,
		        updated_at = CASE
		            WHEN state = 'pending' THEN GREATEST(updated_at, $5)
		            ELSE updated_at
		        END
		  WHERE tenant_id = $1 AND id = $2 AND provider = $3`,
		tenantID, leaseID, provider, sealed, preparedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDynamicSecretLeaseIssuedTx projects a dynsecret.lease.issued event. The
// update activates the preceding pending row and stores only the envelope-sealed
// generated credential. Replaying it against an active/revoked row is a no-op. The
// idempotency key must match the pending row, so a different request can never
// claim another request's deterministic lease id. If an older caller has no
// separate hard expiry, the initial expiry becomes the hard bound.
func (s *Store) ApplyDynamicSecretLeaseIssuedTx(ctx context.Context, tx pgx.Tx, lease DynamicSecretLease) error {
	hardExpiresAt := lease.HardExpiresAt
	if hardExpiresAt.IsZero() {
		hardExpiresAt = lease.ExpiresAt
	}
	updatedAt := lease.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = lease.IssuedAt
	}
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET backend_ref = CASE
		            WHEN state = 'pending' THEN $7
		            ELSE backend_ref
		        END,
		        sealed_credential = CASE
		            WHEN state = 'pending' THEN $8
		            ELSE sealed_credential
		        END,
		        sealed_preparation = CASE
		            WHEN state = 'pending' THEN ''::bytea
		            ELSE sealed_preparation
		        END,
		        state = CASE WHEN state = 'pending' THEN 'active' ELSE state END,
		        issued_at = CASE
		            WHEN state = 'pending' THEN $9
		            ELSE issued_at
		        END,
		        expires_at = CASE
		            WHEN state = 'pending' THEN $10
		            ELSE expires_at
		        END,
		        hard_expires_at = CASE
		            WHEN state = 'pending' THEN $11
		            ELSE hard_expires_at
		        END,
		        last_error = CASE
		            WHEN state = 'pending' THEN ''
		            ELSE last_error
		        END,
		        updated_at = CASE
		            WHEN state = 'pending' THEN $12
		            ELSE updated_at
		        END
		  WHERE tenant_id = $1 AND id = $2 AND idempotency_key = $3
		    AND request_binding = $4 AND provider = $5 AND role = $6
		    AND state IN ('pending', 'active')`,
		lease.TenantID, lease.ID, lease.IdempotencyKey, lease.RequestBinding, lease.Provider, lease.Role,
		lease.BackendRef, lease.SealedCredential, lease.IssuedAt, lease.ExpiresAt, hardExpiresAt, updatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	binding := lease.RequestBinding
	if binding == "" {
		binding = "legacy-unbound"
	}
	if err := s.ApplyDynamicSecretOperationCompletedTx(ctx, tx, lease.TenantID, "issue:"+lease.ID, binding, "issue", lease.ID, updatedAt); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

// ApplyDynamicSecretLeaseIssuanceFailedTx projects a terminal provider creation
// failure. A stale failure replayed after activation cannot downgrade the lease.
func (s *Store) ApplyDynamicSecretLeaseIssuanceFailedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID, lastError string, failedAt time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET state = CASE WHEN state = 'pending' THEN 'failed' ELSE state END,
		        sealed_credential = CASE WHEN state = 'pending' THEN ''::bytea ELSE sealed_credential END,
		        sealed_preparation = CASE WHEN state = 'pending' THEN ''::bytea ELSE sealed_preparation END,
		        last_error = CASE WHEN state = 'pending' THEN $3 ELSE last_error END,
		        updated_at = GREATEST(updated_at, $4)
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, leaseID, lastError, failedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	if err := s.ApplyDynamicSecretIssueOperationFailedTx(ctx, tx, tenantID, leaseID, lastError, failedAt); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

// ApplyDynamicSecretLeaseRenewedTx projects a dynsecret.lease.renewed event. The
// database expiry constraint rejects a renewal past HardExpiresAt, so a replay
// cannot silently widen the provider's configured maximum lease lifetime.
func (s *Store) ApplyDynamicSecretLeaseRenewedTx(ctx context.Context, tx pgx.Tx, tenantID, leaseID string, expiresAt, updatedAt time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET expires_at = CASE
		            WHEN $4 >= updated_at THEN $3
		            ELSE expires_at
		        END,
		        updated_at = GREATEST(updated_at, $4)
		  WHERE tenant_id = $1 AND id = $2 AND state = 'active'`,
		tenantID, leaseID, expiresAt, updatedAt)
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
		  WHERE tenant_id = $1 AND id = $2
		    AND state IN ('active', 'revoked')`,
		tenantID, leaseID, outboxID, revokedAt)
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
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET revocation_status = 'completed', last_error = '',
		        updated_at = GREATEST(updated_at, $3)
		  WHERE tenant_id = $1 AND id = $2 AND state = 'revoked'`,
		tenantID, leaseID, completedAt)
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
	tag, err := tx.Exec(ctx,
		`UPDATE dynamic_secret_leases
		    SET revocation_status = CASE
		            WHEN revocation_status = 'completed' THEN revocation_status
		            ELSE 'failed'
		        END,
		        last_error = CASE
		            WHEN revocation_status = 'completed' THEN last_error
		            ELSE $3
		        END,
		        updated_at = GREATEST(updated_at, $4)
		  WHERE tenant_id = $1 AND id = $2
		    AND state = 'revoked'`,
		tenantID, leaseID, lastError, failedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetDynamicSecretLease returns one lease in its tenant's RLS context.
func (s *Store) GetDynamicSecretLease(ctx context.Context, tenantID, leaseID string) (DynamicSecretLease, error) {
	var lease DynamicSecretLease
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDynamicSecretLease(tx.QueryRow(ctx,
			`SELECT id, tenant_id::text, idempotency_key, request_binding, provider, role, backend_ref,
			        sealed_credential, sealed_preparation, state, issue_outbox_id, revocation_status, revoke_outbox_id, last_error, issued_at,
			        expires_at, hard_expires_at, revoked_at, updated_at
			   FROM dynamic_secret_leases
			  WHERE tenant_id = $1 AND id = $2`,
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
		return scanDynamicSecretLease(tx.QueryRow(ctx,
			`SELECT id, tenant_id::text, idempotency_key, request_binding, provider, role, backend_ref,
			        sealed_credential, sealed_preparation, state, issue_outbox_id, revocation_status, revoke_outbox_id, last_error, issued_at,
			        expires_at, hard_expires_at, revoked_at, updated_at
			   FROM dynamic_secret_leases
			  WHERE tenant_id = $1 AND idempotency_key = $2`,
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
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id::text, idempotency_key, request_binding, provider, role, backend_ref,
			        sealed_credential, sealed_preparation, state, issue_outbox_id, revocation_status, revoke_outbox_id, last_error, issued_at,
			        expires_at, hard_expires_at, revoked_at, updated_at
			   FROM dynamic_secret_leases
			  WHERE tenant_id = $1 AND id > $2
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
			if err := scanDynamicSecretLease(rows, &lease); err != nil {
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
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id::text, idempotency_key, request_binding, provider, role, backend_ref,
			        sealed_credential, sealed_preparation, state, issue_outbox_id, revocation_status, revoke_outbox_id, last_error, issued_at,
			        expires_at, hard_expires_at, revoked_at, updated_at
			   FROM dynamic_secret_leases
			  WHERE tenant_id = $1 AND state = 'active' AND expires_at <= $2
			  ORDER BY expires_at, id
			  LIMIT $3`,
			tenantID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var lease DynamicSecretLease
			if err := scanDynamicSecretLease(rows, &lease); err != nil {
				return err
			}
			out = append(out, lease)
		}
		return rows.Err()
	})
	return out, err
}

func scanDynamicSecretLease(row rowScanner, lease *DynamicSecretLease) error {
	return row.Scan(
		&lease.ID, &lease.TenantID, &lease.IdempotencyKey, &lease.RequestBinding, &lease.Provider, &lease.Role, &lease.BackendRef,
		&lease.SealedCredential, &lease.SealedPreparation, &lease.State, &lease.IssueOutboxID, &lease.RevocationStatus, &lease.RevokeOutboxID, &lease.LastError,
		&lease.IssuedAt, &lease.ExpiresAt, &lease.HardExpiresAt, &lease.RevokedAt,
		&lease.UpdatedAt,
	)
}
