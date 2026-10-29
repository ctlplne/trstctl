// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/eventprotect"
)

type eventProtectionGuardKey struct{}
type eventProtectionGuard struct {
	store  *Store
	tenant string
	active atomic.Bool
	conn   *pgxpool.Conn
}

// WithKeyLock also excludes activation/publication for this tenant. Sharing one
// tenant lock lets nested key use borrow its caller's grant without acquiring a
// second lock-pool connection. Different tenants remain independent.
// The callback performs its nested commands sequentially.
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
	if err := s.validateEventProtectionParents(ctx, tenant.String()); err != nil {
		return err
	}
	if held, _ := ctx.Value(eventProtectionGuardKey{}).(*eventProtectionGuard); held != nil {
		if held.store != s || held.tenant != tenant.String() || !held.active.Load() {
			return errors.New("event protection: invalid nested tenant grant")
		}
		return fn(ctx)
	}
	conn, release, err := s.eventProtectionSession(ctx)
	if err != nil {
		return err
	}
	defer release()
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
	grant := &eventProtectionGuard{store: s, tenant: tenant.String(), conn: conn}
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

func (s *Store) validateEventProtectionParents(ctx context.Context, tenant string) error {
	if service, _ := ctx.Value(tenantServiceFenceKey{}).(*tenantServiceFence); service != nil &&
		(service.store != s || service.tenantID != tenant || !service.active.Load()) {
		return errors.New("event protection: foreign or expired tenant service fence")
	}
	if issuance, _ := ctx.Value(identityIssuanceFenceKey{}).(*identityIssuanceFence); issuance != nil &&
		(issuance.store != s || issuance.tenantID != tenant || !issuance.active.Load()) {
		return errors.New("event protection: foreign or expired identity issuance fence")
	}
	if projection, _ := ctx.Value(projectionSessionKey{}).(*projectionSession); projection != nil &&
		(projection.store != s || !projection.active.Load()) {
		return errors.New("event protection: foreign or expired projection session")
	}
	return nil
}

func (s *Store) eventProtectionSession(ctx context.Context) (*pgxpool.Conn, func(), error) {
	if projection, _ := ctx.Value(projectionSessionKey{}).(*projectionSession); projection != nil {
		if !projection.use.TryLock() {
			return nil, nil, ErrDatastoreBusy
		}
		return projection.conn, projection.use.Unlock, nil
	}
	if issuance, _ := ctx.Value(identityIssuanceFenceKey{}).(*identityIssuanceFence); issuance != nil {
		return issuance.conn, func() {}, nil
	}
	conn, release, err := s.borrowTenantServiceSession(ctx)
	if err != nil || conn != nil {
		return conn, release, err
	}
	release()
	window := s.acquireTimeout
	if window <= 0 {
		window = defaultAcquireTimeout
	}
	bounded, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	conn, err = s.lockSessionPool(ctx).Acquire(bounded)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, fmt.Errorf("%w: event protection lock pool", ErrDatastoreBusy)
	}
	return conn, conn.Release, nil
}
