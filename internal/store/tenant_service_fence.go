// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrTenantServiceBusy is a retryable refusal, not a completed lifecycle change.
var ErrTenantServiceBusy = errors.New("customer work is in progress; retry the same request after it finishes")

type tenantServiceFenceKey struct{}

// TryTenantServiceAdmissionTx protects the short handoff from a session fence
// to durable remote-work evidence. A lost outer session must not allow a
// lifecycle mutation between checking authority and retaining that evidence.
// Try, rather than wait: WithTenant already holds the backup transaction fence.
func (s *Store) TryTenantServiceAdmissionTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	canonical, err := uuid.Parse(tenantID)
	if err != nil {
		return errors.New("store: tenant service admission requires a tenant UUID")
	}
	var admitted bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0))`,
		"tenant-service\x1f"+canonical.String()).Scan(&admitted); err != nil {
		return fmt.Errorf("store: protect remote delivery admission: %w", err)
	}
	if !admitted {
		return ErrTenantServiceBusy
	}
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0))`,
		"tenant-service-commit\x1f"+canonical.String()).Scan(&admitted); err != nil {
		return fmt.Errorf("store: protect remote delivery handoff: %w", err)
	}
	if !admitted {
		return ErrTenantServiceBusy
	}
	return nil
}

// TryTenantLifecycleCommitTx excludes admitted work until this exact SQL
// transaction commits or rolls back. The outer exclusive service session stops
// admission early, but its loss must not let a different connection commit a
// lifecycle change over work admitted in the gap. A separate key avoids waiting
// on the caller's own outer session. Live service sessions hold its shared side.
func (s *Store) TryTenantLifecycleCommitTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	canonical, err := uuid.Parse(tenantID)
	if err != nil {
		return errors.New("store: tenant lifecycle commit requires a tenant UUID")
	}
	var admitted bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`,
		"tenant-service-commit\x1f"+canonical.String()).Scan(&admitted); err != nil {
		return fmt.Errorf("store: protect tenant lifecycle commit: %w", err)
	}
	if !admitted {
		return ErrTenantServiceBusy
	}
	return nil
}

type tenantServiceFence struct {
	store     *Store
	tenantID  string
	exclusive bool
	conn      *pgxpool.Conn
	active    atomic.Bool
	use       sync.Mutex
}

// BeginTenantService keeps an admitted operation on the shared side of the
// tenant's service fence until release. Take it before checking current service
// authority, and release only after the operation and its result writes finish.
// Session locks coordinate replicas without holding a SQL transaction across IO.
func (s *Store) BeginTenantService(ctx context.Context, tenantID string) (context.Context, func(), error) {
	return s.beginTenantServiceFence(ctx, tenantID, false)
}

// WithTenantServiceBarrier refuses promptly if admitted work is still active.
// The callback must check authority and persist the lifecycle decision before
// releasing this exclusive fence. It precedes history/projection/lifecycle locks;
// acquiring it inside a shared operation is an invalid lock upgrade.
func (s *Store) WithTenantServiceBarrier(ctx context.Context, tenantID string, fn func(context.Context) error) error {
	if fn == nil {
		return errors.New("store: tenant service barrier callback is nil")
	}
	ctx, release, err := s.beginTenantServiceFence(ctx, tenantID, true)
	if err != nil {
		return err
	}
	defer release()
	return fn(ctx)
}

func (s *Store) beginTenantServiceFence(ctx context.Context, tenantID string, exclusive bool) (context.Context, func(), error) {
	if s == nil || tenantID == "" {
		return ctx, nil, errors.New("store: tenant service fence is incomplete")
	}
	canonical, err := uuid.Parse(tenantID)
	if err != nil {
		return ctx, nil, errors.New("store: tenant service fence requires a tenant UUID")
	}
	tenantID = canonical.String()
	if held, _ := ctx.Value(tenantServiceFenceKey{}).(*tenantServiceFence); held != nil {
		if held.store != s || held.tenantID != tenantID || !held.active.Load() || (exclusive && !held.exclusive) {
			return ctx, nil, errors.New("store: invalid nested tenant service fence")
		}
		return ctx, func() {}, nil
	}
	if ctx.Value(identityIssuanceFenceKey{}) != nil {
		return ctx, nil, errors.New("store: tenant service fence must precede identity issuance")
	}
	bounded, cancel := context.WithTimeout(ctx, s.acquireTimeout)
	if s.acquireTimeout <= 0 {
		cancel()
		bounded = ctx
		cancel = func() {}
	}
	conn, err := s.lockSessionPool(ctx).Acquire(bounded)
	cancel()
	if err != nil {
		return ctx, nil, fmt.Errorf("%w: acquire tenant service session: %v", ErrDatastoreBusy, err)
	}
	name := "tenant-service\x1f" + tenantID
	query := `SELECT pg_try_advisory_lock_shared(hashtextextended($1,0))`
	unlock := `SELECT pg_advisory_unlock_shared(hashtextextended($1,0))`
	if exclusive {
		query = `SELECT pg_try_advisory_lock(hashtextextended($1,0))`
		unlock = `SELECT pg_advisory_unlock(hashtextextended($1,0))`
	}
	var acquired bool
	if err := conn.QueryRow(ctx, query, name).Scan(&acquired); err != nil {
		// A canceled query may have acquired a session lock before losing its
		// result. Never return that ambiguous session to another borrower.
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		_ = conn.Conn().Close(cleanup)
		stop()
		conn.Release()
		return ctx, nil, fmt.Errorf("store: acquire tenant service fence: %w", err)
	}
	if !acquired {
		conn.Release()
		return ctx, nil, ErrTenantServiceBusy
	}
	if !exclusive {
		// This second shared lock protects against a lifecycle write whose
		// outer session was lost. Acquire both before returning admission.
		err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock_shared(hashtextextended($1,0))`,
			"tenant-service-commit\x1f"+tenantID).Scan(&acquired)
		if err != nil || !acquired {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			_ = conn.Conn().Close(cleanup)
			stop()
			conn.Release()
			if err != nil {
				return ctx, nil, fmt.Errorf("store: acquire service commit session: %w", err)
			}
			return ctx, nil, ErrTenantServiceBusy
		}
	}
	fence := &tenantServiceFence{store: s, tenantID: tenantID, exclusive: exclusive, conn: conn}
	fence.active.Store(true)
	var once sync.Once
	release := func() {
		once.Do(func() {
			fence.active.Store(false)
			fence.use.Lock()
			defer fence.use.Unlock()
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			var released bool
			if !exclusive {
				if err := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock_shared(hashtextextended($1,0))`,
					"tenant-service-commit\x1f"+tenantID).Scan(&released); err != nil || !released {
					_ = conn.Conn().Close(cleanup)
				}
			}
			if err := conn.QueryRow(cleanup, unlock, name).Scan(&released); err != nil || !released {
				_ = conn.Conn().Close(cleanup)
			}
			conn.Release()
		})
	}
	return context.WithValue(ctx, tenantServiceFenceKey{}, fence), release, nil
}

// borrowTenantServiceSession lets sequential identity/projection operations reuse
// the lease's session instead of requiring a second slot in the bounded lock pool.
// Concurrent users fail promptly; they must never issue concurrent pgx commands.
func (s *Store) borrowTenantServiceSession(ctx context.Context) (*pgxpool.Conn, func(), error) {
	fence, _ := ctx.Value(tenantServiceFenceKey{}).(*tenantServiceFence)
	if fence == nil {
		return nil, func() {}, nil
	}
	if fence.store != s || !fence.active.Load() {
		return nil, nil, errors.New("store: tenant service fence has ended or belongs to another store")
	}
	if !fence.use.TryLock() {
		return nil, nil, ErrTenantServiceBusy
	}
	if !fence.active.Load() {
		fence.use.Unlock()
		return nil, nil, errors.New("store: tenant service fence has ended")
	}
	return fence.conn, fence.use.Unlock, nil
}
