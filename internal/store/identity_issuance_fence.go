// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrIdentityIssuanceBusy = errors.New("certificate issuance is in progress for this identity; retry the same lifecycle request")

type identityIssuanceFenceKey struct{}

type identityIssuanceFence struct {
	store      *Store
	tenantID   string
	identityID string
	conn       *pgxpool.Conn
	active     atomic.Bool
}

// IdentityIssuanceFenceHeld is true only for the callback context created by
// WithIdentityIssuanceFence for this store, tenant and identity.
func (s *Store) IdentityIssuanceFenceHeld(ctx context.Context, tenantID, identityID string) bool {
	fence, _ := ctx.Value(identityIssuanceFenceKey{}).(*identityIssuanceFence)
	return fence != nil && fence.active.Load() && fence.store == s && fence.tenantID == tenantID && fence.identityID == identityID
}

// WithIdentityIssuanceFence orders signing and accepted revocation across
// replicas. Contention refuses promptly; a slow issuer does not hold waiting
// database transactions. The callback must perform its commands sequentially.
// Its brief projection writes reuse this session, avoiding a second lock-pool
// acquisition while every host worker could already hold one connection.
func (s *Store) WithIdentityIssuanceFence(ctx context.Context, tenantID, identityID string, fn func(context.Context) error) error {
	if tenantID == "" || identityID == "" || fn == nil {
		return errors.New("store: identity issuance fence is incomplete")
	}
	if service, _ := ctx.Value(tenantServiceFenceKey{}).(*tenantServiceFence); service != nil &&
		(service.store != s || service.tenantID != tenantID || !service.active.Load()) {
		return errors.New("store: identity issuance does not match its active tenant service fence")
	}
	if s.IdentityIssuanceFenceHeld(ctx, tenantID, identityID) {
		return fn(ctx)
	}
	if ctx.Value(identityIssuanceFenceKey{}) != nil {
		return errors.New("store: an issuance callback cannot lock another identity")
	}
	conn, release, err := s.borrowTenantServiceSession(ctx)
	if err != nil {
		return err
	}
	defer release()
	if conn == nil {
		conn, err = s.lockSessionPool(ctx).Acquire(ctx)
		if err != nil {
			return err
		}
		defer conn.Release()
	}
	name := "identity-issuance\x1f" + tenantID + "\x1f" + identityID
	var held bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, name).Scan(&held); err != nil {
		return fmt.Errorf("store: acquire identity issuance fence: %w", err)
	}
	if !held {
		return ErrIdentityIssuanceBusy
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, name); err != nil {
			_ = conn.Conn().Close(unlockCtx)
		}
	}()
	fence := &identityIssuanceFence{store: s, tenantID: tenantID, identityID: identityID, conn: conn}
	fence.active.Store(true)
	defer fence.active.Store(false)
	return fn(context.WithValue(ctx, identityIssuanceFenceKey{}, fence))
}
