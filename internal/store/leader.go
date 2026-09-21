// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// This file holds the leader-election primitive (RESIL-004 / EXC-RESIL-01): a
// PostgreSQL SESSION-scoped advisory lock that lets exactly one control-plane replica
// run the continuous background workers (the projector tailer, the outbox dispatcher,
// the GC sweeps, the CRL scheduler, the audit-retention worker, the snapshot worker)
// while every replica serves reads. Without it, N replicas each ran those workers
// concurrently — the dispatcher is safe via FOR UPDATE SKIP LOCKED and the boot
// catch-up via the projection advisory lock, but the CONTINUOUS tailer/scheduler had
// no coordination, so a non-idempotent apply ordering could interleave.
//
// Why a session-scoped advisory lock: it is held for as long as the holding
// connection lives, and PostgreSQL releases it AUTOMATICALLY when that connection
// drops — so if the leader process crashes or its network partitions, the lock frees
// and a follower acquires it on its next campaign (failover), with no lease timer to
// tune and no split-brain window beyond TCP keepalive. It needs no new datastore
// (no Redis; see docs/operations.md) and reuses the same mechanism migrations and the boot
// catch-up already rely on.

// LeaderAdvisoryLockKey is the fixed PostgreSQL advisory-lock key a replica takes to
// become the singular leader of the continuous background workers (RESIL-004). All
// replicas of one deployment share the database and this key, so at most one holds it
// at a time. The value spells ASCII "ctllea"; operators can see the held lock in
// pg_locks (locktype = 'advisory'). It is a DIFFERENT key from the migration lock
// (ctlmgr) and the projection catch-up lock (ctlprj) so leadership never blocks — and
// is never blocked by — a migration or a boot catch-up.
const LeaderAdvisoryLockKey int64 = 0x63746C6C6561 // "ctllea"

// ErrNotLeader is returned by TryBecomeLeader when another replica already holds the
// leader lock, so the caller knows to stay a follower (serve reads, run no continuous
// workers) and try again later.
var ErrNotLeader = errors.New("store: leadership held by another replica")

// CAProvisionAdvisoryLockKey serializes the FIRST-BOOT issuing-CA provisioning across
// replicas (RESIL-002). When >1 control-plane replica boots at once against an empty
// shared signer key store, each would otherwise generate its own CA key and race to
// seal it, leaving the replicas disagreeing on the CA. Holding this lock across the
// whole provision (generate → seal → persist the cert) makes exactly one replica
// generate the CA; the others then take the lock, find the persisted cert, and reuse
// the same key (the signer reload-on-miss picks it up from the shared store). The
// value spells ASCII "ctlcap"; it is distinct from the migration / catch-up / leader
// keys so provisioning never blocks them.
const CAProvisionAdvisoryLockKey int64 = 0x63746C636170 // "ctlcap"

// WithCAProvisionLock runs fn while holding the CA-provisioning advisory lock on a
// dedicated session connection (RESIL-002), so concurrent first-boot CA provisioning
// across replicas serializes rather than racing to seal different CA keys. The lock
// is released when fn returns (even on error). It is a system operation on the pool,
// like the migration and projection-catch-up locks.
func (s *Store) WithCAProvisionLock(ctx context.Context, fn func(context.Context) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire ca-provision-lock connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", CAProvisionAdvisoryLockKey); err != nil {
		return fmt.Errorf("store: acquire ca-provision lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", CAProvisionAdvisoryLockKey)
	}()
	return fn(ctx)
}

// LeaderLease is an acquired leadership grant: it owns a dedicated pooled connection
// holding the session-scoped advisory lock. While the lease is held, this replica is
// the leader. Lost reports leadership loss (the connection died — e.g. PostgreSQL
// restarted or a partition healed the lock away), and Release relinquishes leadership
// so a follower can take over. A LeaderLease must be Released to free the connection.
type LeaderLease struct {
	conn *pgxpool.Conn
}

// TryBecomeLeader attempts to acquire the leader advisory lock on a dedicated pooled
// connection (RESIL-004). On success it returns a held LeaderLease (this replica is
// now the leader); when another replica holds the lock it returns ErrNotLeader and
// acquires nothing. It uses pg_try_advisory_lock (non-blocking) so a follower's
// campaign returns immediately rather than parking a connection blocked on the lock.
//
// The returned lease owns its connection for the duration of leadership; the caller
// MUST call lease.Release (typically via defer) so the connection returns to the pool
// and the lock frees deterministically on a graceful step-down. If the process dies
// without releasing, PostgreSQL drops the session lock when the connection closes, so
// a follower still recovers.
func (s *Store) TryBecomeLeader(ctx context.Context) (*LeaderLease, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquire leader-lock connection: %w", err)
	}
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", LeaderAdvisoryLockKey).Scan(&got); err != nil {
		conn.Release()
		return nil, fmt.Errorf("store: try leader lock: %w", err)
	}
	if !got {
		conn.Release()
		return nil, ErrNotLeader
	}
	return &LeaderLease{conn: conn}, nil
}

// Healthy reports whether the lease's connection — and therefore the held lock — is
// still alive (RESIL-004). The leader loop calls it on a cadence: if it returns false
// the leader has lost the lock (the connection died) and must stop the continuous
// workers and re-campaign, so two replicas never run them at once. A canceled ctx
// reports unhealthy without touching the connection.
func (l *LeaderLease) Healthy(ctx context.Context) bool {
	if l == nil || l.conn == nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	return l.conn.Ping(ctx) == nil
}

// Release relinquishes leadership: it unlocks the advisory lock and returns the
// connection to the pool (RESIL-004). It is idempotent and safe to call on a lease
// whose connection already died (the unlock is best-effort on a fresh context). After
// Release the replica is a follower again and another replica can become leader.
func (l *LeaderLease) Release() {
	if l == nil || l.conn == nil {
		return
	}
	// Best-effort unlock on a fresh context so the lock drops even if the caller's
	// ctx is done; if the connection is already dead this is a harmless no-op and the
	// server has freed the lock anyway.
	_, _ = l.conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", LeaderAdvisoryLockKey)
	l.conn.Release()
	l.conn = nil
}
