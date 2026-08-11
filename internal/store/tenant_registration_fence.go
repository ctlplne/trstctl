// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// TenantRegistrationSnapshot is the row identity protected by the lifecycle
// fence. CreatedAt is part of the fallback identity for legacy databases whose
// tenant row predates retained tenant.registered producer identities.
type TenantRegistrationSnapshot struct {
	Exists    bool
	Name      string
	EventSeq  uint64
	CreatedAt time.Time
}

func tenantLifecycleLockName(tenantID string) string {
	return "tenant-registration-lifecycle\x1f" + tenantID
}

// lockTenantLifecycleSharedTx is the short transaction fence used by commands
// that belong to one existing tenant registration. It is acquired before row
// locks, so a missing tenants row is still serialized with an offboard or a
// same-UUID registration.
func lockTenantLifecycleSharedTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if tenantID == "" {
		return ErrApplicationSecretTenantEpochMismatch
	}
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`,
		tenantLifecycleLockName(tenantID))
	if err != nil {
		return fmt.Errorf("store: acquire shared tenant lifecycle fence: %w", err)
	}
	return nil
}

// lockTenantLifecycleExclusiveTx serializes registration and offboarding even
// while the tenants row does not exist. Row locks alone cannot cover that gap:
// an INSERT has no old row to wait on.
func lockTenantLifecycleExclusiveTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("store: tenant lifecycle fence requires a tenant id")
	}
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		tenantLifecycleLockName(tenantID))
	if err != nil {
		return fmt.Errorf("store: acquire exclusive tenant lifecycle fence: %w", err)
	}
	return nil
}

func lockLiveTenantRegistrationAfterLifecycleTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := lockLiveTenantRegistrationSnapshotAfterLifecycleTx(ctx, tx, tenantID)
	return err
}

func lockLiveTenantRegistrationSnapshotAfterLifecycleTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) (TenantRegistrationSnapshot, error) {
	var snapshot TenantRegistrationSnapshot
	var eventSequence int64
	err := tx.QueryRow(ctx, `
		SELECT name, event_seq, created_at
		  FROM tenants
		 WHERE tenant_id = $1
		 FOR KEY SHARE`, tenantID).Scan(
		&snapshot.Name, &eventSequence, &snapshot.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return TenantRegistrationSnapshot{}, ErrApplicationSecretTenantEpochMismatch
	}
	if err != nil {
		return TenantRegistrationSnapshot{}, fmt.Errorf("store: lock live tenant registration: %w", err)
	}
	if eventSequence < 0 {
		return TenantRegistrationSnapshot{}, fmt.Errorf("store: tenant registration event sequence is negative")
	}
	snapshot.Exists = true
	snapshot.EventSeq = uint64(eventSequence)
	return snapshot, nil
}

func lockLiveTenantRegistrationTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if err := lockTenantLifecycleSharedTx(ctx, tx, tenantID); err != nil {
		return err
	}
	return lockLiveTenantRegistrationAfterLifecycleTx(ctx, tx, tenantID)
}

// LockLiveTenantRegistrationSnapshotTx takes the shared missing-row-capable
// lifecycle fence before locking the live tenants row. EventSeq is the canonical
// retained tenant.registered position for this lifecycle. A command may resolve
// that event under a fixed history read, then call this method again immediately
// before its own row locks and require the same EventSeq; offboard/re-registration
// cannot cross either critical section.
func (s *Store) LockLiveTenantRegistrationSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) (TenantRegistrationSnapshot, error) {
	if err := lockTenantLifecycleSharedTx(ctx, tx, tenantID); err != nil {
		return TenantRegistrationSnapshot{}, err
	}
	return lockLiveTenantRegistrationSnapshotAfterLifecycleTx(ctx, tx, tenantID)
}

func lockTenantRegistrationForOffboardTx(ctx context.Context, tx pgx.Tx, tenantID string) (bool, error) {
	snapshot, err := lockTenantRegistrationSnapshotTx(ctx, tx, tenantID)
	return snapshot.Exists, err
}

// LockTenantRegistrationSnapshotTx takes the exclusive missing-row-capable
// lifecycle fence, then reads the exact live row under FOR UPDATE. Callers may
// already hold the same xact advisory lock; PostgreSQL makes that re-entrant.
func (s *Store) LockTenantRegistrationSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) (TenantRegistrationSnapshot, error) {
	return lockTenantRegistrationSnapshotTx(ctx, tx, tenantID)
}

func lockTenantRegistrationSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) (TenantRegistrationSnapshot, error) {
	if err := lockTenantLifecycleExclusiveTx(ctx, tx, tenantID); err != nil {
		return TenantRegistrationSnapshot{}, err
	}
	var snapshot TenantRegistrationSnapshot
	var eventSequence int64
	err := tx.QueryRow(ctx, `
		SELECT name, event_seq, created_at
		  FROM tenants
		 WHERE tenant_id = $1
		 FOR UPDATE`, tenantID).Scan(&snapshot.Name, &eventSequence, &snapshot.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TenantRegistrationSnapshot{}, nil
	}
	if err != nil {
		return TenantRegistrationSnapshot{}, fmt.Errorf("store: lock tenant registration snapshot: %w", err)
	}
	if eventSequence < 0 {
		return TenantRegistrationSnapshot{}, fmt.Errorf("store: tenant registration event sequence is negative")
	}
	snapshot.Exists = true
	snapshot.EventSeq = uint64(eventSequence)
	return snapshot, nil
}

// WithTenantRegistrationFence runs a live registration append/project callback
// as the projection owner while holding the tenant lifecycle's exclusive xact
// fence. Event-history coordination stays outside this method so callers can
// obey the global history -> lifecycle -> row lock order.
func (s *Store) WithTenantRegistrationFence(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" || fn == nil {
		return errors.New("store: tenant registration fence is incomplete")
	}
	return s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		if err := lockTenantLifecycleExclusiveTx(ctx, tx, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}
