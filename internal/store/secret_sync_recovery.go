// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
)

// ErrSecretSyncReceiverRecoveryFenced means an event-only recovery has command
// history but not the exact PostgreSQL facts that say whether receiver I/O may
// safely resume.
var ErrSecretSyncReceiverRecoveryFenced = errors.New("store: secret-sync receiver I/O is fenced pending full PostgreSQL recovery")

// FenceSecretSyncReceiverRecovery records the red light before restore mutates
// event history or projections. The row is deployment-local recovery state and
// is deliberately not copied from a PostgreSQL artifact.
func (s *Store) FenceSecretSyncReceiverRecovery(ctx context.Context, reason string) error {
	if reason == "" {
		return errors.New("store: secret-sync recovery fence requires a reason")
	}
	//trstctl:system-query — one cross-tenant system recovery marker has no tenant payload; restore must fence every tenant's receiver lane together (AN-1 exemption).
	tag, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_sync_recovery_authority
		   SET receiver_io_authorized = false, reason = $1, updated_at = now()
		 WHERE singleton`, reason)
	if err != nil {
		return fmt.Errorf("store: fence secret-sync recovery authority: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("store: secret-sync recovery authority row is missing")
	}
	return nil
}

// AuthorizeSecretSyncReceiverRecovery clears the red light only after the full
// restore coordinator has imported exact receiver authority and completed its
// final event replay.
func (s *Store) AuthorizeSecretSyncReceiverRecovery(ctx context.Context) error {
	//trstctl:system-query — one cross-tenant system recovery marker has no tenant payload; full restore authorizes every tenant only after global validation (AN-1 exemption).
	tag, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_sync_recovery_authority
		   SET receiver_io_authorized = true, reason = '', updated_at = now()
		 WHERE singleton`)
	if err != nil {
		return fmt.Errorf("store: authorize secret-sync recovery authority: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("store: secret-sync recovery authority row is missing")
	}
	return nil
}

// RequireSecretSyncReceiverRecoveryAuthorized is the startup/readiness wall.
// Workers repeat the same check transactionally immediately before their
// receiver-start compare-and-swap.
func (s *Store) RequireSecretSyncReceiverRecoveryAuthorized(ctx context.Context) error {
	var authorized bool
	//trstctl:system-query — one cross-tenant system boolean reveals no tenant or command data and blocks every receiver lane after event-only recovery (AN-1 exemption).
	if err := s.SystemPool().QueryRow(ctx, `
		SELECT receiver_io_authorized
		  FROM secret_sync_recovery_authority
		 WHERE singleton`).Scan(&authorized); err != nil {
		return fmt.Errorf("store: read secret-sync recovery authority: %w", err)
	}
	if !authorized {
		return ErrSecretSyncReceiverRecoveryFenced
	}
	return nil
}
