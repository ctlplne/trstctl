package store

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// MigrateAdvisoryLockKey is the fixed PostgreSQL advisory-lock key that every
// instance takes for the duration of a migration run. Because all instances of
// one deployment connect to the same database and use the same key, only one can
// migrate at a time: a replica booting concurrently blocks on this lock until the
// first finishes, then sees the migrations already applied and does nothing. This
// closes the replica-boot race where two instances auto-migrate at once. The
// value spells ASCII "ctlmgr"; operators can see the held lock in pg_locks
// (locktype = 'advisory', objid = the low 32 bits of this key).
const MigrateAdvisoryLockKey int64 = 0x63746C6D6772 // "ctlmgr"

// Migrate applies any pending migrations in order, tracked in the
// schema_migrations ledger (a system, non-tenant table). It runs as the
// connecting (privileged) role, and serializes the whole run on a session-level
// advisory lock (MigrateAdvisoryLockKey) so two instances cannot migrate
// concurrently. Each migration applies in its own transaction together with its
// ledger row, so a crash mid-run leaves the schema and ledger consistent and the
// next run resumes from where it stopped. Migrations are forward-only by policy
// (see docs/migrations.md); recovery from a bad migration is a restore from the
// pre-migration backup.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire migration connection: %w", err)
	}
	defer conn.Release()

	// Take the migration lock; this blocks until any other migrating instance
	// releases it. Holding it on this one session serializes the run.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", MigrateAdvisoryLockKey); err != nil {
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

	names, err := migrationNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		version, err := versionOf(name)
		if err != nil {
			return fmt.Errorf("store: bad migration name %q: %w", name, err)
		}
		if applied[version] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
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
	}
	return nil
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
