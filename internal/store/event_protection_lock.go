// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/eventprotect"
)

type eventProtectionGuardKey struct{}
type eventProtectionGuard struct {
	store  *Store
	tenant string
	active atomic.Bool
}

// WithKeyLock also excludes activation/publication for this tenant. Sharing one
// tenant lock lets nested key use borrow its caller's grant without acquiring a
// second lock-pool connection. Different tenants remain independent.
func (s *Store) WithKeyLock(ctx context.Context, ref eventprotect.KeyRef, fn func(context.Context) error) error {
	key, err := uuid.Parse(ref.ID)
	if err != nil || key == uuid.Nil {
		return errors.New("event protection: key UUID is required")
	}
	return s.WithTenantEventProtection(ctx, ref.TenantID, fn)
}

func (s *Store) WithTenantEventProtection(ctx context.Context, tenantID string, fn func(context.Context) error) error {
	tenant, err := uuid.Parse(tenantID)
	if s == nil || err != nil || tenant == uuid.Nil || fn == nil {
		return errors.New("event protection: tenant and callback are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if held, _ := ctx.Value(eventProtectionGuardKey{}).(*eventProtectionGuard); held != nil {
		if held.store != s || held.tenant != tenant.String() || !held.active.Load() {
			return errors.New("event protection: invalid nested tenant grant")
		}
		return fn(ctx)
	}
	window := s.acquireTimeout
	if window <= 0 {
		window = defaultAcquireTimeout
	}
	bounded, cancel := context.WithTimeout(ctx, window)
	conn, err := s.lockSessionPool(ctx).Acquire(bounded)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: event protection lock pool", ErrDatastoreBusy)
	}
	defer conn.Release()
	identity := "event-protection-tenant:" + tenant.String()
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, identity).Scan(&acquired); err != nil {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = conn.Conn().Close(cleanup)
		return err
	}
	if !acquired {
		return fmt.Errorf("%w: tenant event protection is in use", ErrDatastoreBusy)
	}
	grant := &eventProtectionGuard{store: s, tenant: tenant.String()}
	grant.active.Store(true)
	defer func() {
		grant.active.Store(false)
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		var released bool
		if err := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, identity).Scan(&released); err != nil || !released {
			_ = conn.Conn().Close(cleanup)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(context.WithValue(ctx, eventProtectionGuardKey{}, grant))
}
