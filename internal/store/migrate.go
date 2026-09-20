// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/crypto"
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

// migrationLockTimeout bounds how long any migration statement may WAIT for a
// table lock (OPS-MIG-LOCK-001). An ACCESS-EXCLUSIVE DDL that cannot get its
// lock fails fast with SQLSTATE 55P03 instead of queueing behind live traffic
// and stalling the whole estate (every later statement queues behind a waiting
// ACCESS EXCLUSIVE). The operator retries in a quieter window; docs/migrations.md
// documents the policy. Statement execution itself is unbounded here because
// legitimate migrations (CREATE INDEX CONCURRENTLY on a large table) run long —
// the bounded wait is on LOCKS, not work.
const migrationLockTimeout = "5s"

// configureMigrationSession pins the migration connection's safety posture:
// bounded lock waits, unbounded statement runtime (the pool default
// statement_timeout would kill long CONCURRENTLY builds), and a defensive
// idle-in-transaction bound so an abandoned migration session cannot hold
// locks forever.
func configureMigrationSession(ctx context.Context, conn *pgxpool.Conn) error {
	for _, stmt := range []string{
		"SET lock_timeout = '" + migrationLockTimeout + "'",
		"SET statement_timeout = 0",
		"SET idle_in_transaction_session_timeout = '60s'",
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("store: configure migration session (%s): %w", stmt, err)
		}
	}
	return nil
}

// Migrate applies any pending migrations in order, tracked in the
// schema_migrations ledger (a system, non-tenant table). It runs as the
// connecting (privileged) role, and serializes the whole run on a session-level
// advisory lock (MigrateAdvisoryLockKey) so two instances cannot migrate
// concurrently. By default, each migration applies in its own transaction together
// with its ledger row. A migration may opt into `-- migrate: no-transaction` only
// for idempotent online DDL that PostgreSQL forbids inside a transaction, such as
// CREATE INDEX CONCURRENTLY; the advisory lock still serializes the run, and the
// file must be safe to retry before the ledger row is recorded. Migrations are
// forward-only by policy. The two immutable historical index migrations have
// checksum-bound online execution plans; their original file identity and the
// separate plan digest are both retained (see docs/migrations.md). Recovery from a bad migration is
// a restore from the pre-migration backup.
//
// The ledger records WHAT ran, not merely that something ran (OPS-MIG-CKSUM-001):
// each row carries the migration's file name and a sha256 content digest. Before
// applying anything, an already-applied version whose embedded file no longer
// hashes to what was recorded is a hard error (ErrMigrationChecksumMismatch), and
// a second file claiming an applied version is a hard error
// (ErrMigrationVersionCollision) rather than the silent skip it used to be.
// Ledger rows written before digests existed carry NULL and are ADOPTED on the
// first run of this runner, so an existing deployment upgrades with no backfill
// step and without failing to boot; docs/migrations.md carries the operator
// recovery for a genuine mismatch.
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
	if err := configureMigrationSession(ctx, conn); err != nil {
		return err
	}

	// The ledger is runner-owned rather than a numbered migration: it must exist
	// before any migration can be recorded, so its own shape is upgraded here. The
	// identity and execution-provenance columns are ADDITIVE and NULLABLE on purpose — a deployment
	// installed by an older binary gets them empty (adopted below, not rejected),
	// and a rollback to a pre-checksum binary keeps writing rows this runner can
	// still read. This runs under the advisory lock and the bounded lock_timeout.
	for _, ddl := range []string{
		"CREATE TABLE IF NOT EXISTS schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
		"ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS name text",
		"ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text",
		"ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum_adopted_at timestamptz",
		"ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS execution_plan text",
		"ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS execution_checksum text",
	} {
		if _, err := conn.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("store: create migrations ledger: %w", err)
		}
	}

	led, err := loadMigrationLedger(ctx, conn)
	if err != nil {
		return err
	}

	coreNames, err := migrationNames()
	if err != nil {
		return err
	}
	if err := applyMigrationSet(ctx, conn, led, coreNames, func(name string) ([]byte, error) {
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
		if err := applyMigrationSet(ctx, conn, led, names, func(name string) ([]byte, error) {
			return fs.ReadFile(src, "migrations/"+name)
		}); err != nil {
			return err
		}
	}
	// A migration performs the first format-22 cutover and installs a database
	// floor. Startup raises that floor to the current format (23 includes the AD
	// CS event projection), rejecting writes from rolling older snapshot workers. Repeat the
	// check on every startup to repair an externally restored missing,
	// unvalidated, or same-name-but-weaker floor. Snapshots are disposable, so
	// finding even one legacy row physically purges the whole mixed relation;
	// boot then replays the event log and the current leader publishes one fresh
	// complete generation.
	if err := purgeLegacyReadModelSnapshots(ctx, conn); err != nil {
		return err
	}
	return nil
}

func purgeLegacyReadModelSnapshots(ctx context.Context, conn *pgxpool.Conn) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin snapshot format-floor repair: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Hold the table still from inspection through constraint repair. A rolling
	// older writer either commits before this lock and is purged below, or waits for
	// commit and then meets the repaired current floor. It can never slip into the gap
	// between the purge and the replacement constraint.
	if _, err := tx.Exec(ctx,
		`LOCK TABLE read_model_snapshots IN ACCESS EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("store: lock read-model snapshots for format-floor repair: %w", err)
	}

	var legacy bool
	if err := tx.QueryRow(ctx,
		//trstctl:system-query — cross-tenant system startup inspects only whether any disposable snapshot uses a pre-current format; no tenant ID or payload leaves PostgreSQL (AN-1 exemption).
		`SELECT EXISTS (
			SELECT 1 FROM read_model_snapshots WHERE format_version < $1
		)`, SnapshotFormatVersion).Scan(&legacy); err != nil {
		return fmt.Errorf("store: inspect legacy read-model snapshots: %w", err)
	}
	if legacy {
		//trstctl:system-query — one legacy blob makes the cross-tenant system cache generation unusable; TRUNCATE drops every disposable payload so raw pre-erasure bytes are not merely ignored by restore (AN-1/AN-2 exemption).
		if _, err := tx.Exec(ctx, `TRUNCATE TABLE read_model_snapshots`); err != nil {
			return fmt.Errorf("store: purge legacy read-model snapshots: %w", err)
		}
	}

	const floorConstraint = "read_model_snapshots_format_floor_v22"
	expectedFloorExpression := fmt.Sprintf("format_version>=%d", SnapshotFormatVersion)
	var floorExists, floorMatches, floorValidated bool
	//trstctl:system-query — cross-tenant system migration startup inspects one schema constraint's type, normalized exact CHECK expression, and validation bit; normalization never removes operators or operands, and no tenant rows or payloads leave PostgreSQL (AN-1 exemption).
	if err := tx.QueryRow(ctx, `
		SELECT count(*) = 1,
		       coalesce(bool_and(
		           contype = 'c' AND
		           NOT connoinherit AND
		           regexp_replace(
		               replace(pg_get_expr(conbin, conrelid, true), '::integer', ''),
		               '[[:space:]()]', '', 'g'
		           ) = $2
		       ), false),
		       coalesce(bool_and(convalidated), false)
		  FROM pg_constraint
		 WHERE conrelid = 'read_model_snapshots'::regclass
		   AND conname = $1`, floorConstraint, expectedFloorExpression).
		Scan(&floorExists, &floorMatches, &floorValidated); err != nil {
		return fmt.Errorf("store: inspect snapshot format floor: %w", err)
	}
	if !floorExists {
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			`ALTER TABLE read_model_snapshots
			 ADD CONSTRAINT %s CHECK (format_version >= %d)`,
			floorConstraint, SnapshotFormatVersion,
		)); err != nil {
			return fmt.Errorf("store: restore snapshot format floor: %w", err)
		}
	} else if !floorMatches {
		// A validated constraint with the expected name is not authority unless it
		// is exactly the intended CHECK. Drop and add are one transaction while the
		// table lock remains held, so a weaker lookalike never creates a write gap.
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			`ALTER TABLE read_model_snapshots DROP CONSTRAINT %s`,
			floorConstraint,
		)); err != nil {
			return fmt.Errorf("store: drop mismatched snapshot format floor: %w", err)
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			`ALTER TABLE read_model_snapshots
			 ADD CONSTRAINT %s CHECK (format_version >= %d)`,
			floorConstraint, SnapshotFormatVersion,
		)); err != nil {
			return fmt.Errorf("store: replace mismatched snapshot format floor: %w", err)
		}
	} else if !floorValidated {
		if _, err := tx.Exec(ctx,
			`ALTER TABLE read_model_snapshots
			 VALIDATE CONSTRAINT `+floorConstraint); err != nil {
			return fmt.Errorf("store: validate snapshot format floor: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit snapshot format-floor repair: %w", err)
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
// band (>= 900000) so they cannot collide with core versions; a collision is now
// DETECTED rather than silently skipped — if the version is already recorded under
// a different file name, Migrate fails with ErrMigrationVersionCollision.
// Call before Migrate.
func (s *Store) WithExtraMigrations(fsys fs.FS) *Store {
	s.extraMigrations = append(s.extraMigrations, fsys)
	return s
}

// ErrMigrationChecksumMismatch means an already-applied migration's file no longer
// hashes to what was recorded under that version: a shipped migration was edited
// in place. The run fails closed, because this node's schema and the file the
// binary is reading are no longer the same artefact and the binary cannot know
// which half of the edit actually ran here. docs/migrations.md has the recovery.
var ErrMigrationChecksumMismatch = errors.New("store: applied migration content differs from the embedded file")

// ErrMigrationVersionCollision means two different migration files claim the same
// version — typically an extension migration numbered outside the reserved
// >= 900000 band onto a core version that is already applied. Before the ledger
// recorded names this was a SILENT skip: the colliding migration never ran, and
// nothing said so.
var ErrMigrationVersionCollision = errors.New("store: two migrations claim the same version")

// ledgerRow is one schema_migrations row's identity. An empty string means SQL
// NULL: a row applied by a binary that predates content digests.
type ledgerRow struct {
	name     string
	checksum string
}

// migrationLedger is schema_migrations as it stood at the start of a run: which
// versions are applied, and what was applied under each. It is the difference
// between "migration 42 ran here" and "THIS migration 42 ran here".
type migrationLedger struct {
	applied map[int64]bool
	rows    map[int64]ledgerRow
}

// migrationChecksum is the content digest recorded for an applied migration. Line
// endings are normalized to "\n" and trailing newlines trimmed before hashing, so
// the same file checked out under a different core.autocrlf — or re-saved by an
// editor that adds a final newline — does not read as an edit and refuse to boot.
// The SPDX licence-identifier comment line is excluded too: the relicensing of
// 2026-09-20 rewrote that one line in every shipped migration, and a licence
// notice is metadata about the file, not part of the migration. Nothing else is
// normalized: comments and whitespace are inside the digest, because a shipped
// migration is immutable by policy (docs/migrations.md) and the runner cannot
// tell a comment fix from a DDL edit. Hashing goes through the AN-3 crypto
// boundary rather than crypto/sha256 directly.
func migrationChecksum(body []byte) string {
	normalized := strings.ReplaceAll(string(body), "\r\n", "\n")
	if loc := migrationSPDXLine.FindStringIndex(normalized); loc != nil {
		normalized = normalized[:loc[0]] + normalized[loc[1]:]
	}
	normalized = strings.TrimRight(normalized, "\n")
	return "sha256:" + crypto.SHA256Hex([]byte(normalized))
}

// migrationSPDXLine is the licence-identifier comment a shipped migration carries
// on its first line (or its second, after a `-- migrate:` directive).
var migrationSPDXLine = regexp.MustCompile(`(?m)^-- SPDX-License-Identifier: [A-Za-z0-9.+-]+\n?`)

// previousLicenseIdentifiers are the identifiers shipped migrations carried before
// 2026-09-20: MPL-2.0 for core migrations, LicenseRef-trstctl-EE for the families
// that moved into the core that day.
var previousLicenseIdentifiers = []string{"MPL-2.0", "LicenseRef-trstctl-EE"}

// legacyMigrationChecksums are the digests a binary from before the licence line
// was excluded could have recorded for body: the whole file as it is now, and the
// whole file under each identifier it shipped with earlier. reconcile re-stamps a
// ledger row carrying one of them, because the migration itself is unchanged.
func legacyMigrationChecksums(body []byte) []string {
	normalized := strings.ReplaceAll(string(body), "\r\n", "\n")
	whole := func(text string) string {
		return "sha256:" + crypto.SHA256Hex([]byte(strings.TrimRight(text, "\n")))
	}
	out := []string{whole(normalized)}
	loc := migrationSPDXLine.FindStringIndex(normalized)
	if loc == nil {
		return out
	}
	for _, id := range previousLicenseIdentifiers {
		out = append(out, whole(normalized[:loc[0]]+"-- SPDX-License-Identifier: "+id+"\n"+normalized[loc[1]:]))
	}
	return out
}

// loadMigrationLedger reads the applied set together with each row's recorded
// identity. name/checksum are NULL for rows applied before the ledger carried
// digests; they read back as empty strings and are adopted during this run.
func loadMigrationLedger(ctx context.Context, conn *pgxpool.Conn) (*migrationLedger, error) {
	led := &migrationLedger{applied: make(map[int64]bool), rows: make(map[int64]ledgerRow)}
	rows, err := conn.Query(ctx,
		"SELECT version, coalesce(name, ''), coalesce(checksum, '') FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			v   int64
			row ledgerRow
		)
		if err := rows.Scan(&v, &row.name, &row.checksum); err != nil {
			return nil, err
		}
		led.applied[v] = true
		led.rows[v] = row
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return led, nil
}

// record notes an identity this run just wrote, so later sets in the same run see it.
func (l *migrationLedger) record(version int64, name, checksum string) {
	l.applied[version] = true
	l.rows[version] = ledgerRow{name: name, checksum: checksum}
}

// reconcile decides what an already-applied version means for the file now on
// disk. Three outcomes, and the middle one is the entire upgrade story for
// deployments that predate this ledger shape:
//
//   - a DIFFERENT file claims this version -> ErrMigrationVersionCollision. This
//     is the case that used to be a silent `continue`.
//   - the row carries NO digest (it predates checksums) -> ADOPT the on-disk
//     digest and stamp checksum_adopted_at. An existing install therefore boots
//     normally on first upgrade: no backfill migration, no manual step, no brick.
//   - the row carries a digest that differs -> ErrMigrationChecksumMismatch,
//     unless it is one a pre-2026-09-20 binary recorded for the same bytes under
//     the previous licence header (legacyMigrationChecksums) -> re-stamp it.
//
// Adoption is honest about its limit: it makes today's files the baseline and
// closes the window from here on; it cannot detect an edit made BEFORE the
// upgrade. checksum_adopted_at is how an operator finds the rows that carry that
// caveat, and clearing name/checksum is how an operator deliberately re-adopts.
// Versions in the ledger with no corresponding file are not visited at all, so a
// core-only binary against an ee-migrated database is unaffected.
func (l *migrationLedger) reconcile(ctx context.Context, conn *pgxpool.Conn, version int64, name, checksum string, legacy []string) error {
	row := l.rows[version]
	if row.name != "" && row.name != name {
		return fmt.Errorf("%w: version %d was applied as %q but %q also claims it; extension migrations must use the reserved >= 900000 version band (Store.WithExtraMigrations)",
			ErrMigrationVersionCollision, version, row.name, name)
	}
	if row.checksum == "" {
		if _, err := conn.Exec(ctx,
			"UPDATE schema_migrations SET name = $2, checksum = $3, checksum_adopted_at = now() WHERE version = $1 AND checksum IS NULL",
			version, name, checksum); err != nil {
			return fmt.Errorf("store: adopt content digest for migration %s: %w", name, err)
		}
		l.rows[version] = ledgerRow{name: name, checksum: checksum}
		return nil
	}
	if row.checksum != checksum {
		if slices.Contains(legacy, row.checksum) {
			// Recorded by a binary that hashed the whole file, licence header
			// included; the migration itself is unchanged. Re-stamp the row so the
			// caveat stays visible, exactly like a pre-checksum adoption.
			if _, err := conn.Exec(ctx,
				"UPDATE schema_migrations SET name = $2, checksum = $3, checksum_adopted_at = now() WHERE version = $1 AND checksum = $4",
				version, name, checksum, row.checksum); err != nil {
				return fmt.Errorf("store: re-stamp content digest for migration %s: %w", name, err)
			}
			l.rows[version] = ledgerRow{name: name, checksum: checksum}
			return nil
		}
		return fmt.Errorf("%w: migration %d was applied with %s but %s now hashes to %s; a shipped migration must never be edited in place — add a new migration instead. If this node's schema is confirmed correct, re-adopt the file with: UPDATE schema_migrations SET name = NULL, checksum = NULL WHERE version = %d; (docs/migrations.md)",
			ErrMigrationChecksumMismatch, version, row.checksum, name, checksum, version)
	}
	return nil
}

// applyMigrationSet applies the named migrations that are not yet in the ledger,
// recording each one's version, file name and content digest. read returns a
// migration's SQL body by name. It honors the `-- migrate: no-transaction` opt-out
// exactly as the core path does. A migration whose version is already applied is
// still READ and HASHED — the skip is verified, not assumed.
func applyMigrationSet(ctx context.Context, conn *pgxpool.Conn, led *migrationLedger, names []string, read func(name string) ([]byte, error)) error {
	applied := led.applied
	for _, name := range names {
		version, err := versionOf(name)
		if err != nil {
			return fmt.Errorf("store: bad migration name %q: %w", name, err)
		}
		body, err := read(name)
		if err != nil {
			return err
		}
		checksum := migrationChecksum(body)
		if applied[version] {
			// Forward-only: an applied version is never re-run. But "already
			// applied" is now checked against what was applied.
			if err := led.reconcile(ctx, conn, version, name, checksum, legacyMigrationChecksums(body)); err != nil {
				return err
			}
			continue
		}
		plan, err := historicalOnlinePlan(name, body)
		if err != nil {
			return err
		}
		if plan != nil {
			if err := plan.apply(ctx, conn); err != nil {
				return fmt.Errorf("store: apply online migration %s: %w", name, err)
			}
			if _, err := conn.Exec(ctx, `INSERT INTO schema_migrations
			 (version,name,checksum,execution_plan,execution_checksum) VALUES ($1,$2,$3,$4,$5)`,
				version, name, checksum, "historical-online-v1", migrationChecksum([]byte(plan.executionSQL()))); err != nil {
				return fmt.Errorf("store: record online migration %s: %w", name, err)
			}
			led.record(version, name, checksum)
			continue
		}
		if migrationNoTransaction(body) {
			for _, stmt := range splitMigrationStatements(string(body)) {
				if _, err := conn.Exec(ctx, stmt); err != nil {
					return fmt.Errorf("store: apply no-transaction migration %s: %w", name, err)
				}
			}
			if err := assertConcurrentIndexesValid(ctx, conn, name, body); err != nil {
				return err
			}
			if _, err := conn.Exec(ctx, "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)", version, name, checksum); err != nil {
				return fmt.Errorf("store: record no-transaction migration %s: %w", name, err)
			}
			led.record(version, name, checksum)
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
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)", version, name, checksum); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: record migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("store: commit migration %s: %w", name, err)
		}
		led.record(version, name, checksum)
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

// createIndexConcurrentlyNames extracts the index names a migration builds with
// CREATE [UNIQUE] INDEX CONCURRENTLY.
var createIndexConcurrentlyNames = regexp.MustCompile(
	`(?i)\bcreate\s+(?:unique\s+)?index\s+concurrently\s+(?:if\s+not\s+exists\s+)?"?([a-z0-9_]+)"?`)

// assertConcurrentIndexesValid refuses to record a no-transaction migration as
// applied when one of its CONCURRENTLY-built indexes came out invalid.
//
// A concurrent build that fails partway — a deadlock, a unique violation in live
// data, an operator cancelling it — does not raise here. PostgreSQL leaves the
// index in place with indisvalid = false: it enforces nothing and the planner
// ignores it. The trap is IF NOT EXISTS, which every one of these migrations
// uses: the next run finds the name already present and skips it, so the broken
// index is never rebuilt. Without this check the ledger would then record the
// migration as applied and the failure would be permanent and silent.
//
// That matters most for the UNIQUE ones. An invalid unique index on, say,
// provider_operator_delegations (tenant_id, operator_id, customer_tenant_id,
// operation) means duplicate delegation rows stop being rejected — an
// authorization fact quietly stops being enforced, with nothing in the logs.
// indexValidityQuery reads pg_index/pg_class to confirm a CONCURRENTLY-built
// index came out valid.
//
//trstctl:system-query — cross-tenant system migration check reads only PostgreSQL catalog rows (pg_index/pg_class) for one index name; catalog rows carry no tenant_id and no tenant data, and only two booleans leave PostgreSQL (AN-1 exemption).
const indexValidityQuery = `SELECT i.indisvalid, i.indisready
   FROM pg_index i
   JOIN pg_class c ON c.oid = i.indexrelid
  WHERE c.relname = $1`

func assertConcurrentIndexesValid(ctx context.Context, conn *pgxpool.Conn, name string, body []byte) error {
	// Match against SQL only. These migrations explain themselves in comments,
	// and one of them says "CREATE INDEX CONCURRENTLY cannot run inside a
	// transaction" — prose that reads as a statement to a regex and would have
	// this hunting for an index named "cannot".
	matches := createIndexConcurrentlyNames.FindAllStringSubmatch(stripSQLLineComments(string(body)), -1)
	for _, m := range matches {
		index := m[1]
		var valid, ready bool
		err := conn.QueryRow(ctx,
			indexValidityQuery, index).Scan(&valid, &ready)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: no-transaction migration %s claims to build index %q but it does not exist",
				name, index)
		}
		if err != nil {
			return fmt.Errorf("store: verify index %q from migration %s: %w", index, name, err)
		}
		if !valid || !ready {
			return fmt.Errorf("store: migration %s left index %q invalid (indisvalid=%t indisready=%t); "+
				"the concurrent build failed partway and IF NOT EXISTS would skip rebuilding it forever. "+
				"DROP INDEX CONCURRENTLY %s and re-run", name, index, valid, ready, index)
		}
	}
	return nil
}

// stripSQLLineComments removes -- line comments so statement matching does not
// read the migration's own prose as SQL.
func stripSQLLineComments(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
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
