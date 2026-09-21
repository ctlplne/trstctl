// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

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
	// reservedPool carries only the durable projection tail (and other bounded
	// system workers that opt in through WithReservedPool). Request work never
	// touches it, so a tenant burst that saturates the request pool cannot starve
	// the tail into a retry loop that reports the projection as failed (DP2-056).
	reservedPool *pgxpool.Pool
	// bookkeepingPool carries only the idempotency claim/record/release
	// statements (WithBookkeepingPool). They are tiny transactions whose failure
	// walls a completed command as indeterminate, so they must not compete with
	// the commands themselves for request-pool headroom (DP2-060).
	bookkeepingPool *pgxpool.Pool
	// lockPool holds only the session connections that carry the projection
	// advisory lock (WithProjectionLock). A command waiting for that lock must not
	// occupy a request-pool connection: the holder runs nested transactions on
	// the request pool, and waiters parked there starved it into the acquire
	// window under a burst (DP2-061 convoy).
	lockPool *pgxpool.Pool
	sizes    PoolSizes
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

// reservedPoolMaxConns bounds the system-worker pool: the tail applies one event
// at a time, so two connections leave headroom for a checkpoint advance beside
// an in-flight apply without competing with request work.
const reservedPoolMaxConns = 2

// bookkeepingPoolMaxConns bounds the idempotency bookkeeping pool; each claim,
// record or release is one short statement, so four connections keep pace with
// the API bulkhead's eight workers without holding request-pool connections.
const bookkeepingPoolMaxConns = 4

// lockPoolMaxConns matches the API bulkhead's eight workers: every in-flight
// command can wait for the projection lock without touching the request pool.
const lockPoolMaxConns = 8

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
	pools            PoolSizes
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
// PoolSizes is the per-replica connection budget: the request pool and the four
// dedicated pools. Zero fields keep the defaults (16, 2, 2, 4, 8).
type PoolSizes struct {
	Request, Probe, Reserved, Bookkeeping, Lock int32
}

// Total is the number of PostgreSQL connections one replica may hold.
func (p PoolSizes) Total() int32 { return p.Request + p.Probe + p.Reserved + p.Bookkeeping + p.Lock }

func (p PoolSizes) withDefaults() PoolSizes {
	pick := func(v, def int32) int32 {
		if v > 0 {
			return v
		}
		return def
	}
	return PoolSizes{Request: pick(p.Request, maxConns), Probe: pick(p.Probe, probePoolMaxConns), Reserved: pick(p.Reserved, reservedPoolMaxConns),
		Bookkeeping: pick(p.Bookkeeping, bookkeepingPoolMaxConns), Lock: pick(p.Lock, lockPoolMaxConns)}
}

// WithPoolSizes sets the connection budget (docs/operations.md, "Connection
// budget"). Every pool is opened at startup and pinged, so a PostgreSQL whose
// max_connections cannot honor the total fails the process closed with a
// message naming the budget instead of starving at runtime.
func WithPoolSizes(sizes PoolSizes) OpenOption {
	return func(o *openOptions) { o.pools = sizes }
}

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
	sizes := options.pools.withDefaults()
	cfg.MaxConns = sizes.Request
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	// Server-enforced statement deadline: a runaway query is canceled by
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
	probeCfg.MaxConns = sizes.Probe
	probeCfg.MinConns = 1
	probePool, err := pgxpool.NewWithConfig(ctx, probeCfg)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connect probe pool (connection budget %d per replica: request %d, probe %d, reserved %d, bookkeeping %d, lock %d; raise PostgreSQL max_connections or lower TRSTCTL_POSTGRES_*_CONNS): %w", sizes.Total(), sizes.Request, sizes.Probe, sizes.Reserved, sizes.Bookkeeping, sizes.Lock, err)
	}
	if err := probePool.Ping(ctx); err != nil {
		probePool.Close()
		pool.Close()
		return nil, fmt.Errorf("store: ping probe pool: %w", err)
	}
	reservedCfg := cfg.Copy()
	reservedCfg.MaxConns = sizes.Reserved
	reservedCfg.MinConns = 1
	reservedPool, err := pgxpool.NewWithConfig(ctx, reservedCfg)
	if err != nil {
		probePool.Close()
		pool.Close()
		return nil, fmt.Errorf("store: connect reserved pool (connection budget %d per replica: request %d, probe %d, reserved %d, bookkeeping %d, lock %d; raise PostgreSQL max_connections or lower TRSTCTL_POSTGRES_*_CONNS): %w", sizes.Total(), sizes.Request, sizes.Probe, sizes.Reserved, sizes.Bookkeeping, sizes.Lock, err)
	}
	if err := reservedPool.Ping(ctx); err != nil {
		reservedPool.Close()
		probePool.Close()
		pool.Close()
		return nil, fmt.Errorf("store: ping reserved pool: %w", err)
	}
	bookkeepingCfg := cfg.Copy()
	bookkeepingCfg.MaxConns = sizes.Bookkeeping
	bookkeepingCfg.MinConns = 1
	bookkeepingPool, err := pgxpool.NewWithConfig(ctx, bookkeepingCfg)
	if err != nil {
		reservedPool.Close()
		probePool.Close()
		pool.Close()
		return nil, fmt.Errorf("store: connect bookkeeping pool (connection budget %d per replica: request %d, probe %d, reserved %d, bookkeeping %d, lock %d; raise PostgreSQL max_connections or lower TRSTCTL_POSTGRES_*_CONNS): %w", sizes.Total(), sizes.Request, sizes.Probe, sizes.Reserved, sizes.Bookkeeping, sizes.Lock, err)
	}
	if err := bookkeepingPool.Ping(ctx); err != nil {
		bookkeepingPool.Close()
		reservedPool.Close()
		probePool.Close()
		pool.Close()
		return nil, fmt.Errorf("store: ping bookkeeping pool: %w", err)
	}
	lockCfg := cfg.Copy()
	lockCfg.MaxConns = sizes.Lock
	lockCfg.MinConns = 1
	lockPool, err := pgxpool.NewWithConfig(ctx, lockCfg)
	if err != nil {
		bookkeepingPool.Close()
		reservedPool.Close()
		probePool.Close()
		pool.Close()
		return nil, fmt.Errorf("store: connect lock pool (connection budget %d per replica: request %d, probe %d, reserved %d, bookkeeping %d, lock %d; raise PostgreSQL max_connections or lower TRSTCTL_POSTGRES_*_CONNS): %w", sizes.Total(), sizes.Request, sizes.Probe, sizes.Reserved, sizes.Bookkeeping, sizes.Lock, err)
	}
	if err := lockPool.Ping(ctx); err != nil {
		lockPool.Close()
		bookkeepingPool.Close()
		reservedPool.Close()
		probePool.Close()
		pool.Close()
		return nil, fmt.Errorf("store: ping lock pool: %w", err)
	}
	slog.Info("store: connection budget", slog.Int("request", int(sizes.Request)), slog.Int("probe", int(sizes.Probe)), slog.Int("reserved", int(sizes.Reserved)),
		slog.Int("bookkeeping", int(sizes.Bookkeeping)), slog.Int("lock", int(sizes.Lock)), slog.Int("total_per_replica", int(sizes.Total())))
	return &Store{
		pool:                        pool,
		probePool:                   probePool,
		reservedPool:                reservedPool,
		bookkeepingPool:             bookkeepingPool,
		lockPool:                    lockPool,
		sizes:                       sizes,
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
	pool := s.poolFor(ctx)
	if s.acquireTimeout <= 0 {
		return pool.BeginTx(ctx, options)
	}
	boundedCtx, cancel := context.WithTimeoutCause(ctx, s.acquireTimeout, ErrDatastoreBusy)
	defer cancel()
	tx, err := pool.BeginTx(boundedCtx, options)
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
// canceled by the server-side statement_timeout (SQLSTATE 57014).
func IsBusy(err error) bool {
	if errors.Is(err, ErrDatastoreBusy) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "57014"
}

// IsTransactionRollback reports whether PostgreSQL rolled the statement's
// transaction back because of a concurrent transaction: a serialization
// failure (40001) or a detected deadlock (40P01). Nothing was committed, so the
// same request may be retried as-is; callers must never let it surface as an
// internal error (DP2-059/060).
func IsTransactionRollback(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "40001" || pgErr.Code == "40P01"
}

// SQLState returns the PostgreSQL SQLSTATE carried by err, or "" when err is
// not a PostgreSQL error. It is safe to surface: a five-character class code,
// never a row value.
func SQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// Close releases the connection pool.
func (s *Store) Close() {
	if s.probePool != nil {
		s.probePool.Close()
	}
	if s.reservedPool != nil {
		s.reservedPool.Close()
	}
	if s.bookkeepingPool != nil {
		s.bookkeepingPool.Close()
	}
	if s.lockPool != nil {
		s.lockPool.Close()
	}
	s.pool.Close()
}

// lockSessionPool is where WithProjectionLock parks the connection that holds
// the advisory lock: the lock pool when the store has one, else the pool the
// context is entitled to.
func (s *Store) lockSessionPool(ctx context.Context) *pgxpool.Pool {
	if s.lockPool != nil && !UsesReservedPool(ctx) {
		return s.lockPool
	}
	return s.poolFor(ctx)
}

// PoolStat is one pool's live usage for the operator-facing gauges.
type PoolStat struct {
	Max, Total, Acquired, Idle int32
	EmptyAcquires              int64
}

// PoolStats reports every pool by name (request, probe, reserved, bookkeeping,
// lock) so the server can export trstctl_store_pool_connections.
func (s *Store) PoolStats() map[string]PoolStat {
	out := map[string]PoolStat{}
	add := func(name string, p *pgxpool.Pool) {
		if p == nil {
			return
		}
		st := p.Stat()
		out[name] = PoolStat{Max: st.MaxConns(), Total: st.TotalConns(), Acquired: st.AcquiredConns(), Idle: st.IdleConns(), EmptyAcquires: st.EmptyAcquireCount()}
	}
	add("request", s.pool)
	add("probe", s.probePool)
	add("reserved", s.reservedPool)
	add("bookkeeping", s.bookkeepingPool)
	add("lock", s.lockPool)
	return out
}

// Sizes is the connection budget the store was opened with.
func (s *Store) Sizes() PoolSizes { return s.sizes }

type reservedPoolKey struct{}

type bookkeepingPoolKey struct{}

// WithBookkeepingPool marks ctx so the store serves its transactions from the
// idempotency bookkeeping pool. Only the claim/record/release statements of the
// idempotency protocol opt in; the commands they bracket keep the request pool.
func WithBookkeepingPool(ctx context.Context) context.Context {
	return context.WithValue(ctx, bookkeepingPoolKey{}, true)
}

// UsesBookkeepingPool reports whether ctx was marked by WithBookkeepingPool.
func UsesBookkeepingPool(ctx context.Context) bool {
	v, _ := ctx.Value(bookkeepingPoolKey{}).(bool)
	return v
}

// WithReservedPool marks ctx so the store serves its transactions and direct
// statements from the reserved system-worker pool instead of the request pool.
// Only bounded system workers whose progress must not depend on request-pool
// headroom (the durable projection tail) may opt in; request handlers never do.
func WithReservedPool(ctx context.Context) context.Context {
	return context.WithValue(ctx, reservedPoolKey{}, true)
}

// UsesReservedPool reports whether ctx was marked by WithReservedPool.
func UsesReservedPool(ctx context.Context) bool {
	v, _ := ctx.Value(reservedPoolKey{}).(bool)
	return v
}

// poolFor picks the pool a ctx is entitled to: the reserved pool for marked
// system workers when it exists, the request pool otherwise.
func (s *Store) poolFor(ctx context.Context) *pgxpool.Pool {
	if s.reservedPool != nil && UsesReservedPool(ctx) {
		return s.reservedPool
	}
	if s.bookkeepingPool != nil && UsesBookkeepingPool(ctx) {
		return s.bookkeepingPool
	}
	return s.pool
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
		// canceled. This is especially important when tx reuses the session
		// holding the exclusive backup fence: returning with an open transaction
		// would make the later advisory unlock ambiguous and poison that session.
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tx.Rollback(rollbackCtx)
		cancel()
	}()

	if !ownsExclusiveFence {
		if err := prepareTenantRoleTx(ctx, tx); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+appRole); err != nil {
			return fmt.Errorf("store: set role: %w", err)
		}
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
