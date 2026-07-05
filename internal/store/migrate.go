// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// MigrateAdvisoryLockKey is the fixed PostgreSQL advisory-lock key that every
// instance takes for the duration of a migration run. Because all instances of
// one deployment connect to the same database and use the same key, only one can
// migrate at a time: a replica booting concurrently polls this lock until the
// first finishes, then sees the migrations already applied and does nothing. The
// try-lock polling is intentional: a backend blocked inside pg_advisory_lock can
// hold an open statement transaction, which can deadlock with CREATE INDEX
// CONCURRENTLY. Short pg_try_advisory_lock probes keep waiters out of the way of
// online DDL. This closes the replica-boot race where two instances auto-migrate
// at once. The value spells ASCII "ctlmgr"; operators can see the held lock in
// pg_locks (locktype = 'advisory', objid = the low 32 bits of this key).
const MigrateAdvisoryLockKey int64 = 0x63746C6D6772 // "ctlmgr"

// Migrate applies any pending migrations in order, tracked in the
// schema_migrations ledger (a system, non-tenant table). It runs as the
// connecting (privileged) role, and serializes the whole run on a session-level
// advisory lock (MigrateAdvisoryLockKey) so two instances cannot migrate
// concurrently. By default, each migration applies in its own transaction together
// with its ledger row. A migration may opt into `-- migrate: no-transaction` only
// for idempotent online DDL that PostgreSQL forbids inside a transaction, such as
// CREATE INDEX CONCURRENTLY; the advisory lock still serializes the run, and the
// file must be safe to retry before the ledger row is recorded. Migrations are
// forward-only by policy (see docs/migrations.md); recovery from a bad migration is
// a restore from the pre-migration backup.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire migration connection: %w", err)
	}
	defer conn.Release()

	// Take the migration lock. Use short try-lock probes rather than one blocking
	// pg_advisory_lock statement, because no-transaction migrations may run CREATE
	// INDEX CONCURRENTLY and PostgreSQL waits for older transactions before the
	// index validation phase.
	if err := acquireMigrationLock(ctx, conn, MigrateAdvisoryLockKey); err != nil {
		return fmt.Errorf("store: acquire migration lock: %w", err)
	}
	defer func() {
		// Release on a fresh context so the lock is dropped even if ctx is done.
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", MigrateAdvisoryLockKey)
	}()

	if _, err := conn.Exec(ctx,
		"CREATE TABLE IF NOT EXISTS schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); err != nil {
		return fmt.Errorf("store: create migrations ledger: %w", err)
	}

	applied := make(map[int64]bool)
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	coreNames, err := migrationNames()
	if err != nil {
		return err
	}
	if err := applyMigrationSet(ctx, conn, applied, coreNames, func(name string) ([]byte, error) {
		return migrationFS.ReadFile("migrations/" + name)
	}); err != nil {
		return err
	}
	// Feature-neutral extension migrations (registered via WithExtraMigrations),
	// applied after the core migrations in the same ledger. The core-only build
	// registers none.
	for _, fsys := range s.extraMigrations {
		src := fsys
		names, err := sqlMigrationNames(src)
		if err != nil {
			return err
		}
		if err := applyMigrationSet(ctx, conn, applied, names, func(name string) ([]byte, error) {
			return fs.ReadFile(src, "migrations/"+name)
		}); err != nil {
			return err
		}
	}
	return nil
}

// WithExtraMigrations registers an additional migration source whose "migrations"
// subdirectory holds NNNNNN_*.sql files, applied after the core migrations (in
// registration order) and tracked in the same schema_migrations ledger by
// version. It is a feature-neutral seam — it names nothing edition-specific.
// Extension code, wired only through the tagged ee_attach seam, registers its own
// migrations here; the core-only build registers none, so core applies zero
// extension migrations. Extension migrations must use versions in a reserved high
// band (>= 900000) so they cannot collide with core versions. Call before Migrate.
func (s *Store) WithExtraMigrations(fsys fs.FS) *Store {
	s.extraMigrations = append(s.extraMigrations, fsys)
	return s
}

// applyMigrationSet applies the named migrations that are not yet in applied,
// recording each in the schema_migrations ledger. read returns a migration's SQL
// body by name. It honors the `-- migrate: no-transaction` opt-out exactly as the
// core path does.
func applyMigrationSet(ctx context.Context, conn *pgxpool.Conn, applied map[int64]bool, names []string, read func(name string) ([]byte, error)) error {
	for _, name := range names {
		version, err := versionOf(name)
		if err != nil {
			return fmt.Errorf("store: bad migration name %q: %w", name, err)
		}
		if applied[version] {
			continue
		}
		body, err := read(name)
		if err != nil {
			return err
		}
		if migrationNoTransaction(body) {
			for _, stmt := range splitMigrationStatements(string(body)) {
				if _, err := conn.Exec(ctx, stmt); err != nil {
					return fmt.Errorf("store: apply no-transaction migration %s: %w", name, err)
				}
			}
			if _, err := conn.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
				return fmt.Errorf("store: record no-transaction migration %s: %w", name, err)
			}
			applied[version] = true
			continue
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: record migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("store: commit migration %s: %w", name, err)
		}
		applied[version] = true
	}
	return nil
}

// sqlMigrationNames lists the *.sql files in fsys's "migrations" directory,
// sorted by name (numeric-prefix order).
func sqlMigrationNames(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read extra migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func acquireMigrationLock(ctx context.Context, conn *pgxpool.Conn, key int64) error {
	const interval = 100 * time.Millisecond
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		var ok bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&ok); err != nil {
			return err
		}
		if ok {
			return nil
		}
		timer.Reset(interval)
	}
}

func migrationNoTransaction(body []byte) bool {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "--") {
			continue
		}
		comment := strings.TrimSpace(strings.TrimPrefix(line, "--"))
		comment = strings.ToLower(comment)
		if comment == "migrate: no-transaction" || comment == "migrate: no-tx" {
			return true
		}
	}
	return false
}

func splitMigrationStatements(body string) []string {
	var out []string
	var buf strings.Builder
	for _, line := range strings.SplitAfter(body, "\n") {
		buf.WriteString(line)
		sql := line
		if i := strings.Index(sql, "--"); i >= 0 {
			sql = sql[:i]
		}
		if !strings.Contains(sql, ";") {
			continue
		}
		stmt := strings.TrimSpace(buf.String())
		if stmt != "" {
			out = append(out, stmt)
		}
		buf.Reset()
	}
	if stmt := strings.TrimSpace(buf.String()); stmt != "" {
		out = append(out, stmt)
	}
	return out
}

// PendingMigrations reports, in order, the migrations that Migrate would apply —
// a read-only dry run that mutates nothing (it does not create the ledger or take
// the lock). It backs the pre-migration check (`trstctl --migrate-status`) so an
// operator can see exactly what an upgrade will change and take a backup first.
func (s *Store) PendingMigrations(ctx context.Context) ([]string, error) {
	applied := make(map[int64]bool)
	var hasLedger bool
	if err := s.pool.QueryRow(ctx,
		"SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&hasLedger); err != nil {
		return nil, err
	}
	if hasLedger {
		got, err := s.appliedVersions(ctx)
		if err != nil {
			return nil, err
		}
		applied = got
	}

	names, err := migrationNames()
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, name := range names {
		version, err := versionOf(name)
		if err != nil {
			return nil, fmt.Errorf("store: bad migration name %q: %w", name, err)
		}
		if !applied[version] {
			pending = append(pending, name)
		}
	}
	return pending, nil
}

// migrationNames returns the embedded migration filenames sorted by version.
func migrationNames() ([]string, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) appliedVersions(ctx context.Context) (map[int64]bool, error) {
	rows, err := s.pool.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := make(map[int64]bool)
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// versionOf parses the leading integer of a migration filename ("0001_init.sql"
// -> 1).
func versionOf(name string) (int64, error) {
	base := name
	if i := strings.IndexByte(base, '_'); i > 0 {
		base = base[:i]
	}
	return strconv.ParseInt(base, 10, 64)
}
