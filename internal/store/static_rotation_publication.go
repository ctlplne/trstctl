// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// WithStaticRotationPublicationLock serializes append versus abandonment for
// one command. The callback journals the outcome and never calls a provider.
func (s *Store) WithStaticRotationPublicationLock(ctx context.Context, tenantID, commandID string, fn func(context.Context) error) (retErr error) {
	if tenantID == "" || commandID == "" || fn == nil {
		return errors.New("store: static rotation publication lock is incomplete")
	}
	ctx, end, err := s.BeginTenantService(ctx, tenantID)
	if err != nil {
		return err
	}
	defer end()
	// The outbox already holds an admitted tenant session. Borrow it only
	// while issuing lock statements so nested event custody and projection
	// can borrow the same session in a bounded pool.
	conn, release, err := s.borrowTenantServiceSession(ctx)
	if err != nil {
		return err
	}
	key := "static-rotation-publication:" + tenantID + ":" + commandID
	var held bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key).Scan(&held); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = conn.Conn().Close(cleanup)
		cancel()
		release()
		return err
	}
	release()
	if !held {
		return ErrResourceAdmissionBusy
	}
	defer func() {
		fence := ctx.Value(tenantServiceFenceKey{}).(*tenantServiceFence)
		fence.use.Lock()
		defer fence.use.Unlock()
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var released bool
		if err := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key).Scan(&released); err != nil || !released {
			_ = conn.Conn().Close(cleanup)
			retErr = errors.Join(retErr, fmt.Errorf("store: release static rotation publication lock: %w", ErrTenantServiceBusy))
		}
	}()
	return fn(ctx)
}

// AuthorizeStaticRollbackPublication records the last completed worker step
// before sending the vault append, which can reach the broker without an ACK.
// The caller owns the exact command's publication lock.
func (s *Store) AuthorizeStaticRollbackPublication(ctx context.Context, command SecretStaticRotationCommand, eventID, binding string) error {
	return s.WithTenant(ctx, command.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE application_secret_mutation_fences AS f
			SET rollback_publication_authorized = true
			WHERE f.tenant_id = $1 AND f.secret_name = $2 AND f.event_id = $3
			  AND f.request_binding = $4 AND f.operation = 'rotate' AND f.event_time IS NOT NULL
			  AND EXISTS (SELECT 1 FROM secret_static_rotation_commands AS c
			               WHERE c.tenant_id = $1 AND c.id = $5 AND c.secret_key = $2
			                 AND c.tenant_epoch = $6 AND c.phase = $7)`,
			command.TenantID, command.Key, eventID, binding, command.ID, command.TenantEpoch, command.Phase)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrIdempotencyConflict
		}
		return err
	})
}

// ReleaseFailedStaticRollbackFence releases the unpublished reservation after
// the owner's terminal event has been projected. The caller holds the command
// publication lock and has proved the event was never appended.
func (s *Store) ReleaseFailedStaticRollbackFence(ctx context.Context, command SecretStaticRotationCommand, eventID, binding string) error {
	return s.WithTenant(ctx, command.TenantID, func(tx pgx.Tx) error {
		if err := lockApplicationSecretImportNameTx(ctx, tx, command.TenantID, command.Key); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM application_secret_mutation_fences AS f
			WHERE f.tenant_id = $1 AND f.secret_name = $2 AND f.event_id = $3
			  AND f.request_binding = $4 AND f.operation = 'rotate'
			  AND f.rollback_publication_authorized IS FALSE
			  AND EXISTS (SELECT 1 FROM secret_static_rotation_commands AS c
			               WHERE c.tenant_id = $1 AND c.id = $5 AND c.secret_key = $2
			                 AND c.tenant_epoch = $6 AND c.phase = $7)
			  AND NOT EXISTS (SELECT 1 FROM application_secret_mutation_receipts AS r
			                   WHERE r.tenant_id = $1 AND r.event_id = $3)`,
			command.TenantID, command.Key, eventID, binding, command.ID, command.TenantEpoch, SecretStaticRotationRollbackFailed)
		return err
	})
}
