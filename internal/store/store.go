// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jackc/pgx/v5/pgconn"
	"strconv"
	"time"
	"trstctl.com/trstctl/internal/tenancy"
)

// ZeroUUID is the lowest UUID; it is the keyset-pagination start (no real row
// uses it), so List*Page can express "from the beginning" as id > ZeroUUID.
const ZeroUUID = "00000000-0000-0000-0000-000000000000"

// ErrIdempotencyConflict means a tenant-scoped durable identity already belongs
// to a different command. Reusing the existing row would create read-model /
// outbox disagreement; inserting another row would create a second external
// effect. Callers map this fail-closed condition to HTTP 409.
var ErrIdempotencyConflict = errors.New("store: idempotency identity belongs to a different command")

// IsNotFound reports whether err indicates a missing row (as returned by the
// Get* repositories), letting callers map it to an indistinguishable 404 without
// importing the database driver. ACME DNS-01 intentionally replaces pgx.ErrNoRows
// with a stable tenant-scoped sentinel; preserve the same HTTP classification when
// that sentinel crosses the shared mutation/idempotency wrapper.
func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrACMEDNS01ProviderConfigNotFound)
}

// appRole is the non-superuser role that tenant-scoped operations run as, so
// that row-level security applies (superusers and table owners bypass RLS).
const appRole = "trstctl_app"

// Store is the PostgreSQL-backed repository layer (AN-1). Tenant-scoped reads run
// under row-level security via WithTenant; system operations (migrations,
// projections) use the pool directly.
type Store struct {
	pool *pgxpool.Pool
	// probePool is a tiny dedicated pool for readiness/liveness probes, so a
	// request-pool saturation (AN-7 backpressure: the main pool sheds load with a
	// 503) can never make /readyz report PostgreSQL unreachable. It carries no
	// request work (DP2-054).
	probePool *pgxpool.Pool
	// historyRewriteOperationGate admits only one local contender to the
	// deployment-wide PostgreSQL operation lock. Without it, maxConns local
	// waiters can each pin a session and starve the elected callback's cutover.
	historyRewriteOperationGate chan struct{}
	// acquireTimeout bounds how long begin() waits for a pooled connection.
	acquireTimeout time.Duration
	// extraMigrations are additional migration sources registered through the
	// feature-neutral WithExtraMigrations seam, applied after the core migrations.
	// The core-only build registers none.
	extraMigrations []fs.FS
}

// maxConns bounds the connection pool. It must comfortably exceed the number of
// concurrent tenant-scoped transactions the orchestrator may run at once, since
// idempotent retries (AN-5) deliberately block on one another inside Postgres
// while a key is claimed; too small a pool would starve the waiters.
const maxConns = 16

// probePoolMaxConns bounds the dedicated readiness/liveness probe pool. Two is
// enough for the handful of concurrent probes a /readyz call runs and small
// enough that the probes cannot themselves become a load source.
const probePoolMaxConns = 2

// Bounded-latency defaults (OPS-TIMEOUTS-001): a saturated pool or a runaway
// query fails closed with a structured error instead of hanging a request.
const (
	defaultStatementTimeout = 60 * time.Second
	defaultAcquireTimeout   = 10 * time.Second
)

// ErrDatastoreBusy marks a bounded pool-acquire that timed out: the datastore
// is saturated (or unreachable) and the caller should surface a structured
// 503 rather than queue forever (OPS-TIMEOUTS-001).
var ErrDatastoreBusy = errors.New("store: datastore busy: connection pool acquire timed out")

// OpenOption customizes Open.
type OpenOption func(*openOptions)

type openOptions struct {
	statementTimeout time.Duration
	acquireTimeout   time.Duration
}

// WithStatementTimeout bounds every statement server-side (0 keeps the default).
func WithStatementTimeout(d time.Duration) OpenOption {
	return func(o *openOptions) {
		if d > 0 {
			o.statementTimeout = d
		}
	}
}

// WithAcquireTimeout bounds how long a transaction may wait for a pooled
// connection before failing closed with ErrDatastoreBusy (0 keeps the default).
func WithAcquireTimeout(d time.Duration) OpenOption {
	return func(o *openOptions) {
		if d > 0 {
			o.acquireTimeout = d
		}
	}
}

// Open connects to PostgreSQL at dsn.
func Open(ctx context.Context, dsn string, opts ...OpenOption) (*Store, error) {
	options := openOptions{statementTimeout: defaultStatementTimeout, acquireTimeout: defaultAcquireTimeout}
	for _, opt := range opts {
		opt(&options)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	cfg.MaxConns = maxConns
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	// Server-enforced statement deadline: a runaway query is cancelled by
	// PostgreSQL itself (SQLSTATE 57014), bounding request latency even when a
	// caller forgot a context deadline. Long system operations (read-model
	// rebuild/restore) explicitly widen it inside their own transactions.
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(options.statementTimeout.Milliseconds(), 10)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	// A separate, tiny pool reserved for readiness/liveness probes. It never
	// carries request work, so a saturated request pool (which correctly sheds
	// load with a 503) cannot make a datastore probe time out and drop the whole
	// replica out of rotation (DP2-054).
	probeCfg := cfg.Copy()
	probeCfg.MaxConns = probePoolMaxConns
	probeCfg.MinConns = 1
	probePool, err := pgxpool.NewWithConfig(ctx, probeCfg)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connect probe pool: %w", err)
	}
	if err := probePool.Ping(ctx); err != nil {
		probePool.Close()
		pool.Close()
		return nil, fmt.Errorf("store: ping probe pool: %w", err)
	}
	return &Store{
		pool:                        pool,
		probePool:                   probePool,
		acquireTimeout:              options.acquireTimeout,
		historyRewriteOperationGate: make(chan struct{}, 1),
	}, nil
}

// begin starts a transaction with a bounded pool-acquire window: when the pool
// is saturated the caller gets ErrDatastoreBusy within acquireTimeout instead
// of hanging (OPS-TIMEOUTS-001). The bound covers only BEGIN; statement
// execution stays governed by the caller context + statement_timeout.
func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	return s.beginTx(ctx, pgx.TxOptions{})
}

// beginTx is begin with explicit PostgreSQL transaction options. Callers that
// need a stable statement set (for example an idempotency bind plus an immutable
// scheduler work snapshot) must choose the isolation level at BEGIN; PostgreSQL
// rejects SET TRANSACTION after the backup-fence statement has already run.
func (s *Store) beginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if s.acquireTimeout <= 0 {
		return s.pool.BeginTx(ctx, options)
	}
	boundedCtx, cancel := context.WithTimeoutCause(ctx, s.acquireTimeout, ErrDatastoreBusy)
	defer cancel()
	tx, err := s.pool.BeginTx(boundedCtx, options)
	if err != nil {
		if cause := context.Cause(boundedCtx); errors.Is(cause, ErrDatastoreBusy) && ctx.Err() == nil {
			return nil, fmt.Errorf("%w (acquire window %v)", ErrDatastoreBusy, s.acquireTimeout)
		}
		return nil, err
	}
	return tx, nil
}

// IsBusy reports whether err is a bounded-latency datastore failure a handler
// should surface as a structured 503: a pool-acquire timeout or a statement
// cancelled by the server-side statement_timeout (SQLSTATE 57014).
func IsBusy(err error) bool {
	if errors.Is(err, ErrDatastoreBusy) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "57014"
}

// Close releases the connection pool.
func (s *Store) Close() {
	if s.probePool != nil {
		s.probePool.Close()
	}
	s.pool.Close()
}

// ProbePing checks PostgreSQL reachability on the dedicated probe pool, bounded
// by a short deadline. It is the readiness "db" check: it proves the datastore
// is reachable independently of request-pool saturation, so load shedding on the
// main pool never reads as PostgreSQL being down (DP2-054).
func (s *Store) ProbePing(ctx context.Context) error {
	pool := s.probePool
	if pool == nil {
		pool = s.pool
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("store: probe ping: %w", err)
	}
	return nil
}

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
	// An exclusive backup-fence callback owns one exact PostgreSQL session. A
	// nested tenant read must use that same session: asking a second session for
	// the shared side of the fence would self-deadlock. The private lease is
	// store-bound, single-user, and revoked before the exclusive lock releases;
	// every ordinary caller still takes the shared transaction lock below.
	fenceLease, ownsExclusiveFence := backupWriteFenceLeaseFromContext(ctx, s)
	if ownsExclusiveFence {
		defer fenceLease.releaseUse()
	}

	var (
		tx  pgx.Tx
		err error
	)
	if ownsExclusiveFence {
		tx, err = fenceLease.conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("store: begin tenant transaction under backup write fence: %w", err)
		}
	} else {
		tx, err = s.begin(ctx)
	}
	if err != nil {
		return err
	}
	defer func() {
		// Rollback must still reach PostgreSQL after the request context is
		// cancelled. This is especially important when tx reuses the session
		// holding the exclusive backup fence: returning with an open transaction
		// would make the later advisory unlock ambiguous and poison that session.
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tx.Rollback(rollbackCtx)
		cancel()
	}()

	if !ownsExclusiveFence {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared($1)", BackupWriteFenceAdvisoryLockKey); err != nil {
			return fmt.Errorf("store: acquire backup write fence: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+appRole); err != nil {
		return fmt.Errorf("store: set role: %w", err)
	}
	schema, err := tenancy.PostgresSchema(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("store: resolve tenant route: %w", err)
	}
	if schema != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL search_path TO "+pgx.Identifier{schema}.Sanitize()+", public"); err != nil {
			return fmt.Errorf("store: set tenant search_path: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("store: set tenant: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// WithTenantProjection runs trusted event-derived state maintenance under the
// table-owner role while still pinning the tenant GUC/search path and backup
// fence. It exists for receipt columns that trstctl_app is deliberately forbidden
// to mutate. Event projectors and narrowly verified retention methods may call it;
// every SQL statement still carries tenant_id.
func (s *Store) WithTenantProjection(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	return s.withTenantProjectionTxOptions(ctx, tenantID, pgx.TxOptions{}, fn)
}

// WithTenantProjectionRepeatableRead is the narrow owner-role transaction used
// when several SQL statements together define one immutable receiver snapshot.
// The isolation level is selected at BEGIN, before the shared backup fence is
// acquired, so later concurrent commits cannot appear halfway through the bind.
func (s *Store) WithTenantProjectionRepeatableRead(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	return s.withTenantProjectionTxOptions(ctx, tenantID, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, fn)
}

func (s *Store) withTenantProjectionTxOptions(
	ctx context.Context,
	tenantID string,
	options pgx.TxOptions,
	fn func(pgx.Tx) error,
) error {
	fenceLease, ownsExclusiveFence := backupWriteFenceLeaseFromContext(ctx, s)
	if ownsExclusiveFence {
		defer fenceLease.releaseUse()
	}
	var (
		tx  pgx.Tx
		err error
	)
	if ownsExclusiveFence {
		tx, err = fenceLease.conn.BeginTx(ctx, options)
	} else {
		tx, err = s.beginTx(ctx, options)
	}
	if err != nil {
		return err
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tx.Rollback(rollbackCtx)
		cancel()
	}()
	if !ownsExclusiveFence {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared($1)", BackupWriteFenceAdvisoryLockKey); err != nil {
			return fmt.Errorf("store: acquire backup write fence for projection: %w", err)
		}
	}
	schema, err := tenancy.PostgresSchema(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("store: resolve tenant projection route: %w", err)
	}
	if schema != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL search_path TO "+pgx.Identifier{schema}.Sanitize()+", public"); err != nil {
			return fmt.Errorf("store: set tenant projection search_path: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("store: set tenant projection: %w", err)
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
