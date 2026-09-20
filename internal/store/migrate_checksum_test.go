// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// OPS-MIG-CKSUM-001 acceptance.
//
// The ledger used to record that migration N ran, not WHAT ran: an in-place edit
// to an already-applied migration was invisible on a deployed node, so two nodes
// could hold different schemas and both believe they were current, and a second
// file claiming an applied version was skipped in silence. These tests drive the
// real migration runner against a real (embedded) PostgreSQL through the public
// WithExtraMigrations seam, so the behaviour proven here is the behaviour a
// booting node gets.

// ledgerProbeVersion sits in the reserved extension band (>= 900000) and above
// every version any ee/ migration set uses, so the probe cannot collide with a
// real migration.
const ledgerProbeVersion = 990001

const (
	ledgerProbeBodyV1 = "CREATE TABLE IF NOT EXISTS migration_ledger_probe (id bigint PRIMARY KEY);\n"
	// The same file, edited AFTER it was applied. This is the edit a version-only
	// ledger cannot see.
	ledgerProbeBodyV2 = "CREATE TABLE IF NOT EXISTS migration_ledger_probe (id bigint PRIMARY KEY);\n" +
		"ALTER TABLE migration_ledger_probe ADD COLUMN IF NOT EXISTS edited_in_place boolean;\n"
)

type shippedMigrationDigest struct {
	name     string
	expected string
}

// immutableShippedMigrationDigests is deliberately narrow. It records only the
// post-SCHEMA-006 files that were already deployed before AUD-148 tried to move
// their DDL into 0187/0188. The online-safety scanner may grandfather one only
// while its bytes still match this exact digest; any edit loses the exemption.
var immutableShippedMigrationDigests = []shippedMigrationDigest{
	{name: "0152_application_secret_fence_actor.sql", expected: "sha256:aaf49224e7c99f01dfcbe2fcc43f20f2ef031e240c84e2759a00d22d25afc401"},
	{name: "0156_dynamic_secret_tenant_epoch_recovery.sql", expected: "sha256:fada6e0ae2d6a012fb82dbe7b9be632deceb83bf5d9ffa18fcc7066800e3e295"},
	{name: "0159_secret_rotation_schedule_registration_identity.sql", expected: "sha256:6d0b7092cdc6f8dc2af2ae6728701c8b0a57e34a1e673d3a593a14601897cdfc"},
	{name: "0179_enrollment_diagnostic_workflows.sql", expected: "sha256:c48eef73f1b6d542bddd10a57ac96c9f671834678bcd1acacf71d3a757cd0f38"},
}

func normalizedMigrationDigest(raw []byte) string {
	return store.MigrationChecksumForTest(raw)
}

// wholeFileDigest is the digest a binary from before 2026-09-20 recorded: the
// whole file, licence header included. Kept here as the fixture for the ledger
// rows such a binary left behind.
func wholeFileDigest(raw []byte) string {
	normalized := strings.ReplaceAll(string(raw), "\r\n", "\n")
	normalized = strings.TrimRight(normalized, "\n")
	return "sha256:" + crypto.SHA256Hex([]byte(normalized))
}

// TestMigrationChecksumIgnoresLicenseHeader: the relicensing of 2026-09-20 rewrote
// the SPDX comment in every shipped migration. That line is metadata about the
// file, so it must be outside the digest — while any change to the SQL stays inside.
func TestMigrationChecksumIgnoresLicenseHeader(t *testing.T) {
	t.Parallel()
	bare := normalizedMigrationDigest([]byte(ledgerProbeBodyV1))
	for _, tc := range []struct{ header, kept string }{
		{"-- SPDX-License-Identifier: MPL-2.0\n", ""},
		{"-- SPDX-License-Identifier: BUSL-1.1\n", ""},
		{"-- SPDX-License-Identifier: LicenseRef-trstctl-EE\n", ""},
		// The directive stays inside the digest; only the licence line leaves it.
		{"-- migrate: no-transaction\n-- SPDX-License-Identifier: BUSL-1.1\n", "-- migrate: no-transaction\n"},
	} {
		got := normalizedMigrationDigest([]byte(tc.header + ledgerProbeBodyV1))
		want := normalizedMigrationDigest([]byte(tc.kept + ledgerProbeBodyV1))
		if got != want {
			t.Fatalf("digest with header %q = %s, want %s (the licence line must not be part of the identity)", tc.header, got, want)
		}
	}
	if normalizedMigrationDigest([]byte(ledgerProbeBodyV2)) == bare {
		t.Fatal("a DDL edit hashed the same as the original; the digest must still see the SQL")
	}
	if normalizedMigrationDigest([]byte("-- a comment\n"+ledgerProbeBodyV1)) == bare {
		t.Fatal("an ordinary comment hashed the same as the original; only the SPDX line is outside the digest")
	}
}

// TestMigrationLedgerRestampsRowsHashedUnderPreviousLicenseHeader is the
// EXISTING-DEPLOYMENT path across the relicensing: a node whose ledger rows were
// written by a binary that hashed the whole file — MPL-2.0 header included — must
// boot on the BUSL-1.1 files, re-stamp those rows, and still refuse a real edit.
func TestMigrationLedgerRestampsRowsHashedUnderPreviousLicenseHeader(t *testing.T) {
	ctx := context.Background()
	dsn := createFreshMigrationDatabase(t)
	const busl = "-- SPDX-License-Identifier: BUSL-1.1\n"
	const mpl = "-- SPDX-License-Identifier: MPL-2.0\n"

	current := openMigrator(t, dsn, ledgerProbeFS(busl+ledgerProbeBodyV1))
	if err := current.Migrate(ctx); err != nil {
		t.Fatalf("Migrate with the relicensed probe migration: %v", err)
	}
	// Rewrite the row the way the previous binary left it: the whole-file digest
	// of the MPL-headed file, never adopted.
	legacy := wholeFileDigest([]byte(mpl + ledgerProbeBodyV1))
	if _, err := current.SystemPool().Exec(ctx,
		"UPDATE schema_migrations SET checksum = $2, checksum_adopted_at = NULL WHERE version = $1", int64(ledgerProbeVersion), legacy); err != nil {
		t.Fatalf("plant the pre-relicensing ledger row: %v", err)
	}

	upgraded := openMigrator(t, dsn, ledgerProbeFS(busl+ledgerProbeBodyV1))
	if err := upgraded.Migrate(ctx); err != nil {
		t.Fatalf("Migrate over a ledger row recorded under the previous licence header must succeed, got: %v", err)
	}
	var checksum string
	var adoptedAt *string
	if err := current.SystemPool().QueryRow(ctx,
		"SELECT checksum, checksum_adopted_at::text FROM schema_migrations WHERE version = $1", int64(ledgerProbeVersion)).Scan(&checksum, &adoptedAt); err != nil {
		t.Fatalf("read the re-stamped ledger row: %v", err)
	}
	if want := normalizedMigrationDigest([]byte(busl + ledgerProbeBodyV1)); checksum != want {
		t.Fatalf("re-stamped checksum = %s, want the current digest %s", checksum, want)
	}
	if adoptedAt == nil {
		t.Fatal("a re-stamped ledger row carries no checksum_adopted_at; the rows whose digest was translated rather than observed must stay visible to an operator")
	}

	// The tolerance is exactly one line wide: the same legacy row against an
	// edited body is still the in-place edit the ledger exists to refuse.
	if _, err := current.SystemPool().Exec(ctx,
		"UPDATE schema_migrations SET checksum = $2, checksum_adopted_at = NULL WHERE version = $1", int64(ledgerProbeVersion), legacy); err != nil {
		t.Fatalf("re-plant the pre-relicensing ledger row: %v", err)
	}
	edited := openMigrator(t, dsn, ledgerProbeFS(busl+ledgerProbeBodyV2))
	if err := edited.Migrate(ctx); !errors.Is(err, store.ErrMigrationChecksumMismatch) {
		t.Fatalf("Migrate with an edited body over a legacy row = %v, want ErrMigrationChecksumMismatch", err)
	}
}

func isExactImmutableShippedMigration(name string, raw []byte) bool {
	got := normalizedMigrationDigest(raw)
	for _, migration := range immutableShippedMigrationDigests {
		if migration.name == name {
			return got == migration.expected
		}
	}
	return false
}

// TestShippedMigrationDigestsStayImmutable is the regression for QA's real
// preserved-volume upgrade failure. AUD-148 moved index work into migrations
// 0187/0188, but it also edited four earlier files in place. A node that had
// already recorded the original bytes correctly refused to boot. These exact
// historical digests are now a review-visible ratchet: future index or schema
// work must use a new migration instead of silently rewriting deployed history.
func TestShippedMigrationDigestsStayImmutable(t *testing.T) {
	t.Parallel()
	migrations := os.DirFS("migrations")
	for _, tc := range immutableShippedMigrationDigests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := fs.ReadFile(migrations, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			got := normalizedMigrationDigest(raw)
			if got != tc.expected {
				t.Fatalf("%s digest = %s, want deployed digest %s; restore the file and add a new numbered migration", tc.name, got, tc.expected)
			}
		})
	}
}

func ledgerProbeFS(body string) fstest.MapFS {
	return fstest.MapFS{
		"migrations/990001_ledger_probe.sql": &fstest.MapFile{Data: []byte(body)},
	}
}

// openMigrator opens a store against dsn, optionally registering an extension
// migration source through the feature-neutral seam.
func openMigrator(t *testing.T, dsn string, extra fstest.MapFS) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if extra != nil {
		s.WithExtraMigrations(extra)
	}
	return s
}

// TestMigrationLedgerRecordsWhatRan: a fresh apply records the file name and the
// sha256 content digest alongside the version, and does NOT mark those rows as
// adopted — a fresh apply OBSERVES the digest, it does not grandfather it.
func TestMigrationLedgerRecordsWhatRan(t *testing.T) {
	ctx := context.Background()
	dsn := createFreshMigrationDatabase(t)
	s := openMigrator(t, dsn, nil)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate on a fresh database: %v", err)
	}

	var unidentified int
	if err := s.SystemPool().QueryRow(ctx,
		"SELECT count(*) FROM schema_migrations WHERE name IS NULL OR checksum IS NULL OR checksum NOT LIKE 'sha256:%'").Scan(&unidentified); err != nil {
		t.Fatalf("read the migration ledger: %v", err)
	}
	if unidentified != 0 {
		t.Fatalf("%d ledger rows record a version without the file name and sha256 content digest that produced it; an in-place edit to those migrations would be undetectable", unidentified)
	}

	var adopted int
	if err := s.SystemPool().QueryRow(ctx,
		"SELECT count(*) FROM schema_migrations WHERE checksum_adopted_at IS NOT NULL").Scan(&adopted); err != nil {
		t.Fatalf("read the migration ledger: %v", err)
	}
	if adopted != 0 {
		t.Fatalf("%d rows on a FRESH install are stamped checksum-adopted; a fresh apply must observe the digest at apply time, not grandfather it", adopted)
	}

	// Steady state: a second run re-hashes every applied file, matches, changes nothing.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate over an unmodified migration set: %v", err)
	}
}

// TestMigrationLedgerRejectsEditedAppliedMigration is the core reproduction: apply
// a migration, edit its body, re-run. The old runner skipped on version alone and
// booted a node whose schema nobody could describe. It must now fail closed — and
// the documented break-glass must recover it without a new binary.
func TestMigrationLedgerRejectsEditedAppliedMigration(t *testing.T) {
	ctx := context.Background()
	dsn := createFreshMigrationDatabase(t)

	first := openMigrator(t, dsn, ledgerProbeFS(ledgerProbeBodyV1))
	if err := first.Migrate(ctx); err != nil {
		t.Fatalf("Migrate with the probe migration: %v", err)
	}

	edited := openMigrator(t, dsn, ledgerProbeFS(ledgerProbeBodyV2))
	if err := edited.Migrate(ctx); !errors.Is(err, store.ErrMigrationChecksumMismatch) {
		t.Fatalf("Migrate after an in-place edit to applied migration %d = %v, want ErrMigrationChecksumMismatch", ledgerProbeVersion, err)
	}

	// Break-glass (docs/migrations.md): an operator who has confirmed this node's
	// schema clears the recorded identity; the next boot re-adopts the file and
	// STAMPS the row, so the grandfathering stays visible afterwards.
	if _, err := first.SystemPool().Exec(ctx,
		"UPDATE schema_migrations SET name = NULL, checksum = NULL WHERE version = $1", int64(ledgerProbeVersion)); err != nil {
		t.Fatalf("clear the ledger identity: %v", err)
	}
	if err := edited.Migrate(ctx); err != nil {
		t.Fatalf("Migrate after the operator re-adopted version %d: %v", ledgerProbeVersion, err)
	}
	var adoptedAt *string
	if err := first.SystemPool().QueryRow(ctx,
		"SELECT checksum_adopted_at::text FROM schema_migrations WHERE version = $1", int64(ledgerProbeVersion)).Scan(&adoptedAt); err != nil {
		t.Fatalf("read the re-adopted ledger row: %v", err)
	}
	if adoptedAt == nil {
		t.Fatal("a re-adopted ledger row carries no checksum_adopted_at stamp; the rows whose digest was never verified against what actually ran would be invisible to an operator")
	}
}

// TestMigrationLedgerAdoptsPreChecksumRowsOnUpgrade is the EXISTING-DEPLOYMENT
// path. A ledger written by a binary that predates content digests has NULL in
// the identity columns. Failing closed on those rows would brick every install on
// upgrade, so they are adopted and stamped instead — and enforced from then on.
func TestMigrationLedgerAdoptsPreChecksumRowsOnUpgrade(t *testing.T) {
	ctx := context.Background()
	dsn := createFreshMigrationDatabase(t)
	s := openMigrator(t, dsn, nil)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate on a fresh database: %v", err)
	}

	// Rewind the ledger to the shape a pre-checksum install has: version and
	// applied_at only.
	if _, err := s.SystemPool().Exec(ctx,
		"UPDATE schema_migrations SET name = NULL, checksum = NULL, checksum_adopted_at = NULL"); err != nil {
		t.Fatalf("simulate a pre-checksum ledger: %v", err)
	}
	var legacy int
	if err := s.SystemPool().QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&legacy); err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	if legacy == 0 {
		t.Fatal("the simulated pre-checksum ledger is empty; this test would prove nothing")
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("upgrading an install whose ledger predates content digests must ADOPT, not fail: %v", err)
	}
	var unadopted int
	if err := s.SystemPool().QueryRow(ctx,
		"SELECT count(*) FROM schema_migrations WHERE checksum IS NULL OR checksum_adopted_at IS NULL").Scan(&unadopted); err != nil {
		t.Fatalf("read the migration ledger: %v", err)
	}
	if unadopted != 0 {
		t.Fatalf("%d pre-checksum rows were left without an adopted, stamped digest; the window for an undetected in-place edit would stay open", unadopted)
	}

	// Adopted digests are enforced like any other from here on.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate after adoption: %v", err)
	}
}

// TestMigrationLedgerRejectsVersionCollision: an extension migration numbered onto
// an applied core version used to hit `if applied[version] { continue }` — it never
// ran, and nothing said so. It must now stop the run.
func TestMigrationLedgerRejectsVersionCollision(t *testing.T) {
	ctx := context.Background()
	dsn := createFreshMigrationDatabase(t)
	collide := fstest.MapFS{
		"migrations/0004_collides_with_core.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE IF NOT EXISTS migration_collision_probe (id bigint PRIMARY KEY);\n"),
		},
	}
	s := openMigrator(t, dsn, collide)
	if err := s.Migrate(ctx); !errors.Is(err, store.ErrMigrationVersionCollision) {
		t.Fatalf("Migrate with an extension migration numbered onto an applied core version = %v, want ErrMigrationVersionCollision", err)
	}
	var exists bool
	if err := s.SystemPool().QueryRow(ctx,
		"SELECT to_regclass('public.migration_collision_probe') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatalf("check the colliding migration's table: %v", err)
	}
	if exists {
		t.Fatal("the colliding migration ran; a version collision must stop the run, not apply a second file under an already-recorded version")
	}
}

// TestMigrationLedgerDollarQuotedMigrationsStayTransactional is a RATCHET, not a
// bug fix: it PASSES on the tree that introduces it, and is here to keep a latent
// hazard latent. splitMigrationStatements — used only on the no-transaction path —
// splits on any ';' outside a '--' comment and carries no dollar-quote state, so a
// `DO $$ ... ; ... $$;` body in a no-transaction migration would be cut into
// fragments and either fail or half-apply. Today the $$-quoted migrations (0001,
// 0071, 0092) are all transactional, so the splitter never sees them.
func TestMigrationLedgerDollarQuotedMigrationsStayTransactional(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	dollarQuoted := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("migrations", entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		body := string(raw)
		if !strings.Contains(body, "$$") {
			continue
		}
		dollarQuoted++
		lower := strings.ToLower(body)
		if strings.Contains(lower, "-- migrate: no-transaction") || strings.Contains(lower, "-- migrate: no-tx") {
			t.Errorf("%s has a $$-quoted body AND opts into -- migrate: no-transaction; splitMigrationStatements has no dollar-quote state and would cut the body at the first ';' inside $$. Either drop the no-transaction opt-out or teach the splitter dollar quoting first", entry.Name())
		}
	}
	if dollarQuoted == 0 {
		t.Fatal("no $$-quoted migration found; the scan matched nothing, so this ratchet is vacuous — re-check the detection")
	}
}
