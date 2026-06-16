package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ZeroUUID is the lowest UUID; it is the keyset-pagination start (no real row
// uses it), so List*Page can express "from the beginning" as id > ZeroUUID.
const ZeroUUID = "00000000-0000-0000-0000-000000000000"

// IsNotFound reports whether err indicates a missing row (as returned by the
// Get* repositories), letting callers map it to a 404 without importing the
// database driver.
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// appRole is the non-superuser role that tenant-scoped operations run as, so
// that row-level security applies (superusers and table owners bypass RLS).
const appRole = "trstctl_app"

// Store is the PostgreSQL-backed repository layer (AN-1). Tenant-scoped reads run
// under row-level security via WithTenant; system operations (migrations,
// projections) use the pool directly.
type Store struct {
	pool *pgxpool.Pool
}

// maxConns bounds the connection pool. It must comfortably exceed the number of
// concurrent tenant-scoped transactions the orchestrator may run at once, since
// idempotent retries (AN-5) deliberately block on one another inside Postgres
// while a key is claimed; too small a pool would starve the waiters.
const maxConns = 16

// Open connects to PostgreSQL at dsn.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// SystemPool exposes the underlying connection pool for SYSTEM operations only:
// cross-tenant, RLS-BYPASSING work such as migrations, projection writes, and the
// outbox/idempotency sweepers. Queries run through this pool are NOT confined by
// row-level security (the pool connects as the table owner), so a tenant-scoped
// query must NEVER use it — use WithTenant instead, which assumes the RLS role and
// sets the tenant GUC. The name is deliberately explicit (TENANT-005): a reader or
// reviewer can grep for SystemPool to find every RLS-bypassing access site and
// confirm each is a legitimate system path, not a leaked tenant query.
func (s *Store) SystemPool() *pgxpool.Pool { return s.pool }

// Pool is a deprecated alias for SystemPool, retained for existing call sites
// (mostly test setup that is itself system-scoped). New code must call SystemPool
// so the RLS-bypassing intent is explicit at the call site (TENANT-005).
//
// Deprecated: use SystemPool.
func (s *Store) Pool() *pgxpool.Pool { return s.SystemPool() }

// WithTenant runs fn in a transaction scoped to tenantID: it assumes the RLS
// role and sets the trstctl.tenant_id session variable, so row-level security
// confines every query in fn to that tenant.
func (s *Store) WithTenant(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+appRole); err != nil {
		return fmt.Errorf("store: set role: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("store: set tenant: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TruncateTenants empties the tenants read model (used when rebuilding a
// projection). It is a system operation.
func (s *Store) TruncateTenants(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, "TRUNCATE tenants")
	return err
}
