// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/eventprotect"
)

// WithKeyLock implements eventprotect.KeyLocker using the bounded lock pool.
// Tenant UUID aliases share a lock. This session lock is intentionally outside
// a tenant transaction: the custodian must still verify destruction evidence
// after offboarding has erased that tenant's relational rows.
func (s *Store) WithKeyLock(ctx context.Context, ref eventprotect.KeyRef, fn func(context.Context) error) error {
	tenant, tenantErr := uuid.Parse(ref.TenantID)
	key, keyErr := uuid.Parse(ref.ID)
	if tenantErr != nil || keyErr != nil || tenant == uuid.Nil || key == uuid.Nil || fn == nil {
		return errors.New("event protection: tenant, key and callback are required")
	}
	acquireWindow := s.acquireTimeout
	if acquireWindow <= 0 {
		acquireWindow = defaultAcquireTimeout
	}
	bounded, cancel := context.WithTimeout(ctx, acquireWindow)
	conn, err := s.lockSessionPool(ctx).Acquire(bounded)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: event protection lock pool", ErrDatastoreBusy)
	}
	defer conn.Release()
	identity := "event-protection-key:" + tenant.String() + ":" + key.String()
	var held bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, identity).Scan(&held); err != nil {
		// An interrupted statement could have acquired a session lock before
		// its response was lost. Never return that session to the pool.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
		defer closeCancel()
		_ = conn.Conn().Close(closeCtx)
		return err
	}
	if !held {
		return fmt.Errorf("%w: event protection key is in use", ErrDatastoreBusy)
	}
	defer func() {
		unlockCtx, unlockCancel := context.WithTimeout(context.Background(), time.Second)
		defer unlockCancel()
		var unlocked bool
		if err := conn.QueryRow(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, identity).Scan(&unlocked); err != nil || !unlocked {
			_ = conn.Conn().Close(unlockCtx)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(ctx)
}
