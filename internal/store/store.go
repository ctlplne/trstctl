package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// appRole is the non-superuser role that tenant-scoped operations run as, so
// that row-level security applies (superusers and table owners bypass RLS).
const appRole = "certctl_app"

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

// Pool exposes the underlying pool for system (cross-tenant, RLS-bypassing)
// operations such as migrations and projection writes.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// WithTenant runs fn in a transaction scoped to tenantID: it assumes the RLS
// role and sets the certctl.tenant_id session variable, so row-level security
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
	if _, err := tx.Exec(ctx, "SELECT set_config('certctl.tenant_id', $1, true)", tenantID); err != nil {
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
