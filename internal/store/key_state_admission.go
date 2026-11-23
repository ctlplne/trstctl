// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// These are deliberately different PostgreSQL advisory resources. Session
// admission protects authentication before the projection transaction begins;
// the transaction lock keeps key retirement blocked through commit even if
// that outer session disappears.
const (
	keyStateAdmissionLockKey int64 = 0x6b737461746541
	keyStateCommitLockKey    int64 = 0x6b737461746542
)

type KeyStateAdmissionMode uint8

const (
	KeyStateShared KeyStateAdmissionMode = iota + 1
	KeyStateExclusive
)

type keyStateAdmissionContextKey struct{}
type keyStateOwnerContextKey struct{}
type keyStateReplayContextKey struct{}

type keyStateOwner struct {
	store                *Store
	tx                   pgx.Tx
	tenantID             string
	mode                 KeyStateAdmissionMode
	marker               string
	mu                   sync.Mutex
	projectionActivities map[string]string // event ID -> durable operation ID
}

type keyStateReplayGrant struct {
	store  *Store
	tx     pgx.Tx
	marker string
}

type keyStateAdmissionGrant struct {
	store  *Store
	mode   KeyStateAdmissionMode
	active atomic.Bool
	check  func(context.Context) error
}

// HasKeyStateOwnerContext identifies a caller that arrived with an already
// opened key-state transaction. Ingress adapters must not acquire a history
// session after this marker unless the caller preheld that history read wall.
func (s *Store) HasKeyStateOwnerContext(ctx context.Context) bool {
	owner, _ := ctx.Value(keyStateOwnerContextKey{}).(*keyStateOwner)
	return s != nil && owner != nil
}

var ErrKeyStateAdmissionUnavailable = errors.New("store: key-state admission is unavailable")
var ErrKeyStateOwnerUnavailable = errors.New("store: key-state transaction owner is unavailable")

// WithGlobalKeyStateAdmission is the outermost key-state operation fence. A
// nested shared user may borrow an exclusive grant; a shared holder may never
// upgrade, since it could deadlock a queued key-state transition.
func (s *Store) WithGlobalKeyStateAdmission(
	ctx context.Context,
	mode KeyStateAdmissionMode,
	fn func(context.Context) error,
) (retErr error) {
	if s == nil || fn == nil || mode != KeyStateShared && mode != KeyStateExclusive {
		return ErrKeyStateAdmissionUnavailable
	}
	if parent, ok := ctx.Value(keyStateAdmissionContextKey{}).(*keyStateAdmissionGrant); ok {
		if parent.store != s || !parent.active.Load() || mode == KeyStateExclusive && parent.mode != KeyStateExclusive {
			return ErrKeyStateAdmissionUnavailable
		}
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		return fn(ctx)
	}
	// A tail may use the two-connection reserved pool for its history view and
	// projection transaction. Keep the outer key-state session on the lock pool
	// so it cannot consume either reserved transaction connection.
	lockPool := s.lockPool
	if lockPool == nil {
		lockPool = s.poolFor(ctx)
	}
	conn, err := lockPool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire key-state admission session: %w", err)
	}
	shared := mode == KeyStateShared
	locked := false
	acquireUncertain := false
	defer func() {
		if acquireUncertain {
			retErr = errors.Join(retErr, discardHistoryRewriteSession(conn))
			return
		}
		if !locked {
			conn.Release()
			return
		}
		if err := releaseHistoryRewriteLock(conn, keyStateAdmissionLockKey, shared); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("store: release key-state admission: %w", err), discardHistoryRewriteSession(conn))
			return
		}
		conn.Release()
	}()
	if err := acquireHistoryRewriteLock(ctx, conn, keyStateAdmissionLockKey, shared); err != nil {
		acquireUncertain = true
		return fmt.Errorf("store: acquire key-state admission: %w", err)
	}
	locked = true
	grant := &keyStateAdmissionGrant{store: s, mode: mode,
		check: func(checkCtx context.Context) error {
			_, err := conn.Exec(checkCtx, `SELECT 1`)
			return err
		}}
	grant.active.Store(true)
	defer grant.active.Store(false)
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	return fn(context.WithValue(ctx, keyStateAdmissionContextKey{}, grant))
}

// LockGlobalKeyStateCommitTx takes the transaction half of the same admission.
// The caller owns tx and must keep it open through its final apply/commit. The
// distinct advisory key makes it safe to hold A and B on separate connections.
func (s *Store) LockGlobalKeyStateCommitTx(ctx context.Context, tx pgx.Tx, mode KeyStateAdmissionMode) error {
	if s == nil || tx == nil || mode != KeyStateShared && mode != KeyStateExclusive {
		return ErrKeyStateAdmissionUnavailable
	}
	grant, ok := ctx.Value(keyStateAdmissionContextKey{}).(*keyStateAdmissionGrant)
	if !ok || grant.store != s || !grant.active.Load() || mode == KeyStateExclusive && grant.mode != KeyStateExclusive {
		return ErrKeyStateAdmissionUnavailable
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	query := `SELECT pg_advisory_xact_lock_shared($1)`
	if mode == KeyStateExclusive {
		query = `SELECT pg_advisory_xact_lock($1)`
	}
	if _, err := tx.Exec(ctx, query, keyStateCommitLockKey); err != nil {
		return fmt.Errorf("store: acquire key-state commit lock: %w", err)
	}
	if err := grant.check(ctx); err != nil {
		return fmt.Errorf("%w: outer session ended before transaction admission: %v", ErrKeyStateAdmissionUnavailable, err)
	}
	return nil
}

// AssertGlobalKeyStateAdmissionAlive is called immediately before committing
// a transaction admitted under A. B remains held by PostgreSQL through its
// commit, so a lost outer session cannot silently authorize later work.
func (s *Store) AssertGlobalKeyStateAdmissionAlive(ctx context.Context) error {
	grant, ok := ctx.Value(keyStateAdmissionContextKey{}).(*keyStateAdmissionGrant)
	if !ok {
		return nil
	}
	if grant.store != s || !grant.active.Load() {
		return ErrKeyStateAdmissionUnavailable
	}
	if err := grant.check(ctx); err != nil {
		return fmt.Errorf("%w: outer session ended before commit: %v", ErrKeyStateAdmissionUnavailable, err)
	}
	return nil
}

// BindKeyStateOwnerTx joins the outer session grant to this exact transaction.
// The random, transaction-local marker prevents a copied Go context from
// authorizing a different or already-completed database transaction.
func (s *Store) BindKeyStateOwnerTx(
	ctx context.Context, tx pgx.Tx, tenantID string, mode KeyStateAdmissionMode,
) (context.Context, error) {
	if s == nil || tx == nil || tenantID == "" {
		return nil, ErrKeyStateOwnerUnavailable
	}
	if err := s.LockGlobalKeyStateCommitTx(ctx, tx, mode); err != nil {
		return nil, err
	}
	marker := uuid.NewString()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.key_state_owner', $1, true)`, marker); err != nil {
		return nil, fmt.Errorf("%w: set transaction marker: %v", ErrKeyStateOwnerUnavailable, err)
	}
	if err := s.AssertGlobalKeyStateAdmissionAlive(ctx); err != nil {
		return nil, err
	}
	owner := &keyStateOwner{store: s, tx: tx, tenantID: tenantID, mode: mode, marker: marker}
	return context.WithValue(ctx, keyStateOwnerContextKey{}, owner), nil
}

// RequireKeyStateOwnerTx is the store sink's final check before it changes key
// state. A bare transaction, another tenant, a stale marker or a copied token
// on another transaction cannot pass.
func (s *Store) RequireKeyStateOwnerTx(
	ctx context.Context, tx pgx.Tx, tenantID string, required KeyStateAdmissionMode,
) error {
	if replay, ok := ctx.Value(keyStateReplayContextKey{}).(*keyStateReplayGrant); ok {
		if replay == nil || replay.store != s || replay.tx != tx || tenantID == "" {
			return ErrKeyStateOwnerUnavailable
		}
		if err := s.AssertGlobalKeyStateAdmissionAlive(ctx); err != nil {
			return err
		}
		var marker string
		if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.key_state_replay_owner', true)`).Scan(&marker); err != nil || marker != replay.marker {
			return ErrKeyStateOwnerUnavailable
		}
		return nil
	}
	owner, ok := ctx.Value(keyStateOwnerContextKey{}).(*keyStateOwner)
	if !ok || owner == nil || owner.store != s || owner.tx != tx ||
		owner.tenantID != tenantID || required == KeyStateExclusive && owner.mode != KeyStateExclusive ||
		owner.mode != KeyStateShared && owner.mode != KeyStateExclusive {
		return ErrKeyStateOwnerUnavailable
	}
	if err := s.AssertGlobalKeyStateAdmissionAlive(ctx); err != nil {
		return err
	}
	var marker string
	if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.key_state_owner', true)`).Scan(&marker); err != nil {
		return fmt.Errorf("%w: transaction marker unavailable: %v", ErrKeyStateOwnerUnavailable, err)
	}
	if marker != owner.marker {
		return ErrKeyStateOwnerUnavailable
	}
	return nil
}

func (s *Store) keyStateReplayContext(ctx context.Context, tx pgx.Tx) (context.Context, error) {
	marker := uuid.NewString()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.key_state_replay_owner', $1, true)`, marker); err != nil {
		return nil, fmt.Errorf("%w: set rebuild transaction marker: %v", ErrKeyStateOwnerUnavailable, err)
	}
	return context.WithValue(ctx, keyStateReplayContextKey{}, &keyStateReplayGrant{store: s, tx: tx, marker: marker}), nil
}
