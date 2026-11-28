// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5"
)

var ErrTenantEventTxUnavailable = errors.New("store: tenant event transaction is unavailable")

type tenantEventTxContextKey struct{}

type tenantEventTxScope struct {
	mu       sync.Mutex
	store    *Store
	tenantID string
	tx       pgx.Tx
	active   bool
}

// WithTenantEvent gives an event producer a tenant transaction and an append
// context bound to that exact transaction. The context expires before commit.
func (s *Store) WithTenantEvent(ctx context.Context, tenantID string,
	fn func(context.Context, pgx.Tx) error,
) error {
	if fn == nil {
		return ErrTenantEventTxUnavailable
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		scope := &tenantEventTxScope{store: s, tenantID: tenantID, tx: tx, active: true}
		defer func() {
			scope.mu.Lock()
			scope.active = false
			scope.mu.Unlock()
		}()
		return fn(context.WithValue(ctx, tenantEventTxContextKey{}, scope), tx)
	})
}

// UseTenantEventTx borrows the active transaction only for this store and
// tenant. found distinguishes a direct producer from an expired or mismatched
// scoped context; the latter must fail closed before event publication.
func (s *Store) UseTenantEventTx(ctx context.Context, tenantID string,
	fn func(pgx.Tx) error,
) (found bool, err error) {
	scope, ok := ctx.Value(tenantEventTxContextKey{}).(*tenantEventTxScope)
	if !ok {
		return false, nil
	}
	if scope == nil || fn == nil {
		return true, ErrTenantEventTxUnavailable
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if !scope.active || scope.store != s || scope.tenantID != tenantID || scope.tx == nil {
		return true, ErrTenantEventTxUnavailable
	}
	return true, fn(scope.tx)
}
