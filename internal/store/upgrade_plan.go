// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
)

// The upgrade plan (A246): what this binary would change in the database
// before it is allowed to, read without changing anything — the migrations it
// has not applied (core and extension), which of them an older binary might
// not survive, applied migrations whose files no longer match, versions the
// database carries that this binary does not know, indexes a failed
// concurrent build left invalid, and whether another run holds the migration
// lock.

// UpgradeMigration is one migration this binary would apply.
type UpgradeMigration struct {
	Version int64
	Name    string
	// Destructive marks a statement an older binary may not survive or that
	// loses data: a dropped table, column, type, schema or view, a rename, a
	// truncate or delete, a column type change, a new NOT NULL.
	Destructive bool
	// Transactional is false for a `-- migrate: no-transaction` migration,
	// which cannot roll back as one unit.
	Transactional bool
}

// UpgradePlan is the database's position against this binary's migrations.
type UpgradePlan struct {
	// SchemaVersion is the highest applied core migration version.
	SchemaVersion int64
	// BinaryVersion is the highest core migration version this binary ships.
	BinaryVersion int64
	Pending       []UpgradeMigration
	// ChecksumMismatches name applied migrations whose files changed since.
	ChecksumMismatches []string
	// NewerThanBinary are applied versions, core or extension, this binary has
	// no file for: a newer binary migrated this database. Every build
	// registers the same extension sources, so an unknown extension version
	// is a newer one too.
	NewerThanBinary []int64
	// InvalidIndexes are indexes a failed concurrent build left behind.
	InvalidIndexes []string
	// LockHeld reports that another run holds the migration lock now.
	LockHeld bool
}

// PendingNames lists the plan's pending migrations by file name, in order.
func (p UpgradePlan) PendingNames() []string {
	out := make([]string, 0, len(p.Pending))
	for _, m := range p.Pending {
		out = append(out, m.Name)
	}
	return out
}

// extensionMigrationBand is where WithExtraMigrations versions start.
const extensionMigrationBand = 900000

var destructiveMigration = regexp.MustCompile(`(?i)\b(drop\s+(table|column|type|schema|view|materialized\s+view)|rename\s+(to|column)|truncate|delete\s+from|alter\s+column\s+\S+\s+(set\s+data\s+)?type|set\s+not\s+null)\b`)

// classifyMigration reads a migration's SQL, comments stripped, for
// statements an older binary may not survive.
func classifyMigration(body []byte) (destructive, transactional bool) {
	return destructiveMigration.MatchString(stripSQLLineComments(string(body))), !migrationNoTransaction(body)
}

// migrationPosition compares the ledger with every migration this binary
// ships, core and extension, reading files and the ledger only.
func (s *Store) migrationPosition(ctx context.Context) (UpgradePlan, error) {
	var out UpgradePlan
	applied := map[int64]string{}
	var hasLedger bool
	if err := s.pool.QueryRow(ctx, "SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&hasLedger); err != nil {
		return out, err
	}
	if hasLedger {
		rows, err := s.pool.Query(ctx, "SELECT version, coalesce(checksum, '') FROM schema_migrations")
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var version int64
			var checksum string
			if err := rows.Scan(&version, &checksum); err != nil {
				rows.Close()
				return out, err
			}
			applied[version] = checksum
			if version < extensionMigrationBand && version > out.SchemaVersion {
				out.SchemaVersion = version
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
	}
	known := map[int64]bool{}
	for _, fsys := range append([]fs.FS{migrationFS}, s.extraMigrations...) {
		names, err := sqlMigrationNames(fsys)
		if err != nil {
			return out, err
		}
		for _, name := range names {
			version, err := versionOf(name)
			if err != nil {
				return out, fmt.Errorf("store: bad migration name %q: %w", name, err)
			}
			known[version] = true
			if version < extensionMigrationBand && version > out.BinaryVersion {
				out.BinaryVersion = version
			}
			body, err := fs.ReadFile(fsys, "migrations/"+name)
			if err != nil {
				return out, err
			}
			if checksum, ok := applied[version]; ok {
				if checksum != "" && checksum != migrationChecksum(body) && !slices.Contains(legacyMigrationChecksums(body), checksum) {
					out.ChecksumMismatches = append(out.ChecksumMismatches, name)
				}
				continue
			}
			destructive, transactional := classifyMigration(body)
			out.Pending = append(out.Pending, UpgradeMigration{Version: version, Name: name, Destructive: destructive, Transactional: transactional})
		}
	}
	sort.Slice(out.Pending, func(i, j int) bool { return out.Pending[i].Version < out.Pending[j].Version })
	for version := range applied {
		if !known[version] {
			out.NewerThanBinary = append(out.NewerThanBinary, version)
		}
	}
	slices.Sort(out.NewerThanBinary)
	return out, nil
}

// invalidIndexQuery lists the indexes on the search path, as an unqualified
// DROP INDEX resolves them, that a failed concurrent build left invalid.
//
//trstctl:system-query — cross-tenant system upgrade check reads only PostgreSQL catalog rows (pg_index/pg_class) for index names; catalog rows carry no tenant_id and no tenant data, and only index names leave PostgreSQL (AN-1 exemption).
const invalidIndexQuery = `SELECT c.relname FROM pg_index i
	JOIN pg_class c ON c.oid = i.indexrelid
	WHERE pg_table_is_visible(c.oid) AND NOT (i.indisvalid AND i.indisready)
	ORDER BY c.relname`

// UpgradePlan reads the whole plan. It writes nothing; its probe of the
// migration lock releases the lock at once when it gets it.
func (s *Store) UpgradePlan(ctx context.Context) (UpgradePlan, error) {
	out, err := s.migrationPosition(ctx)
	if err != nil {
		return out, err
	}
	rows, err := s.pool.Query(ctx, invalidIndexQuery)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return out, err
		}
		out.InvalidIndexes = append(out.InvalidIndexes, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return out, err
	}
	defer conn.Release()
	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", MigrateAdvisoryLockKey).Scan(&acquired); err != nil {
		return out, err
	}
	if acquired {
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", MigrateAdvisoryLockKey); err != nil {
			return out, err
		}
	}
	out.LockHeld = !acquired
	return out, nil
}
