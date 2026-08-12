// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestLegacyReadModelSnapshotPayloadsArePurgedOnUpgradeAndEveryStartupAUD114(t *testing.T) {
	ctx := context.Background()
	dsn := createFreshMigrationDatabase(t)
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open fresh snapshot-purge database: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}

	const floorConstraint = "read_model_snapshots_format_floor_v22"
	const rawSubject = "aud114-raw-erasure-subject"
	dropFloor := func() {
		t.Helper()
		if _, err := s.SystemPool().Exec(ctx,
			`ALTER TABLE read_model_snapshots DROP CONSTRAINT IF EXISTS `+floorConstraint); err != nil {
			t.Fatalf("drop snapshot format floor: %v", err)
		}
	}
	seedMixedSnapshotFormats := func() {
		t.Helper()
		if _, err := s.SystemPool().Exec(ctx, `
			INSERT INTO read_model_snapshots
			       (tenant_id, covered_seq, format_version, payload)
			VALUES ('a1140000-0000-4000-8000-000000000001', 21, 21,
			        jsonb_build_object('owners', jsonb_build_array(
			          jsonb_build_object('name', $1::text)))),
			       ('a1140000-0000-4000-8000-000000000002', 22, $2,
			        '{"safe":"current"}'::jsonb)`,
			rawSubject, store.SnapshotFormatVersion); err != nil {
			t.Fatalf("seed mixed snapshot formats: %v", err)
		}
	}
	assertPurged := func(stage string) {
		t.Helper()
		var rows, rawRows int
		if err := s.SystemPool().QueryRow(ctx, `
			SELECT count(*),
			       count(*) FILTER (WHERE payload::text LIKE '%' || $1 || '%')
			  FROM read_model_snapshots`, rawSubject).Scan(&rows, &rawRows); err != nil {
			t.Fatalf("inspect snapshots after %s: %v", stage, err)
		}
		if rows != 0 || rawRows != 0 {
			t.Fatalf("snapshots after %s = rows:%d raw-subject-rows:%d, want physical relation empty",
				stage, rows, rawRows)
		}
	}
	assertValidatedFloor := func(stage string) {
		t.Helper()
		var constraintType, expression string
		var validated bool
		if err := s.SystemPool().QueryRow(ctx, `
			SELECT contype::text, convalidated,
			       regexp_replace(
			           replace(pg_get_expr(conbin, conrelid, true), '::integer', ''),
			           '[[:space:]()]', '', 'g'
			       )
			  FROM pg_constraint
			 WHERE conrelid = 'read_model_snapshots'::regclass
			   AND conname = $1`, floorConstraint).
			Scan(&constraintType, &validated, &expression); err != nil {
			t.Fatalf("inspect snapshot format floor after %s: %v", stage, err)
		}
		if constraintType != "c" || !validated || expression != "format_version>=23" {
			t.Fatalf("snapshot format floor after %s = type:%q validated:%t expression:%q",
				stage, constraintType, validated, expression)
		}
	}
	assertLegacyWriteRejected := func(stage string) {
		t.Helper()
		if _, err := s.SystemPool().Exec(ctx, `
			INSERT INTO read_model_snapshots
			       (tenant_id, covered_seq, format_version, payload)
			VALUES ('a1140000-0000-4000-8000-000000000099', 21, 21,
			        jsonb_build_object('owners', jsonb_build_array(
			          jsonb_build_object('name', $1::text))))`, rawSubject); err == nil {
			t.Fatalf("pre-current snapshot write succeeded after %s", stage)
		}
	}

	// Re-run the numbered migration as an upgrade over a database that already
	// contains a legacy raw payload. The migration drops the whole disposable
	// relation contents, including a mixed current-format neighbor.
	dropFloor()
	seedMixedSnapshotFormats()
	if _, err := s.SystemPool().Exec(ctx,
		`DELETE FROM schema_migrations WHERE version = 160`); err != nil {
		t.Fatalf("rewind snapshot purge migration ledger: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("upgrade Migrate over legacy snapshot: %v", err)
	}
	assertPurged("format-23 upgrade")
	assertValidatedFloor("format-23 upgrade")
	assertLegacyWriteRejected("format-23 upgrade")

	// Simulate an old replica writing v21 after migration 160 was ledgered. The
	// missing-floor fixture models an externally restored/altered schema; normal
	// rolling old writers are rejected by the validated database constraint.
	// The recurring startup guard must still purge the row and repair the floor
	// without relying on migration 160 to run a second time.
	dropFloor()
	seedMixedSnapshotFormats()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("startup Migrate over rolling-upgrade legacy snapshot: %v", err)
	}
	assertPurged("recurring startup guard")
	assertValidatedFloor("recurring startup guard")
	assertLegacyWriteRejected("recurring startup guard")

	// Repairing a missing floor over a clean current-format cache must not delete
	// that cache or impose an accidental full-replay tax.
	dropFloor()
	if _, err := s.SystemPool().Exec(ctx, `
		INSERT INTO read_model_snapshots
		       (tenant_id, covered_seq, format_version, payload)
		VALUES ('a1140000-0000-4000-8000-000000000003', 22, $1,
		        '{"safe":"current-only"}'::jsonb)`,
		store.SnapshotFormatVersion); err != nil {
		t.Fatalf("seed current snapshot: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("ordinary startup Migrate: %v", err)
	}
	var currentRows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM read_model_snapshots`).Scan(&currentRows); err != nil {
		t.Fatalf("count current snapshots: %v", err)
	}
	if currentRows != 1 {
		t.Fatalf("current-format snapshots after ordinary startup = %d, want 1", currentRows)
	}
	assertValidatedFloor("missing-floor repair over current v23")

	// An interrupted online schema repair may leave the right constraint present
	// but NOT VALID. Startup replaces the old v22 floor and preserves the clean v23 row.
	if _, err := s.SystemPool().Exec(ctx,
		`ALTER TABLE read_model_snapshots DROP CONSTRAINT `+floorConstraint); err != nil {
		t.Fatalf("drop validated floor before NOT VALID fixture: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`ALTER TABLE read_model_snapshots
		 ADD CONSTRAINT `+floorConstraint+` CHECK (format_version >= 22) NOT VALID`); err != nil {
		t.Fatalf("seed unvalidated snapshot format floor: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("startup Migrate over unvalidated floor: %v", err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM read_model_snapshots`).Scan(&currentRows); err != nil {
		t.Fatalf("count current snapshots after floor validation: %v", err)
	}
	if currentRows != 1 {
		t.Fatalf("current-format snapshots after floor validation = %d, want 1", currentRows)
	}
	assertValidatedFloor("unvalidated-floor repair")
	assertLegacyWriteRejected("unvalidated-floor repair")
}

func TestMigrateReplacesMalformedValidatedSnapshotFloorAUD114(t *testing.T) {
	ctx := context.Background()
	dsn := createFreshMigrationDatabase(t)
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open fresh malformed-floor database: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}

	const floorConstraint = "read_model_snapshots_format_floor_v22"
	if _, err := s.SystemPool().Exec(ctx,
		`ALTER TABLE read_model_snapshots DROP CONSTRAINT `+floorConstraint); err != nil {
		t.Fatalf("drop correct snapshot floor: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`ALTER TABLE read_model_snapshots
		 ADD CONSTRAINT `+floorConstraint+` CHECK (format_version >= 1)`); err != nil {
		t.Fatalf("seed malformed validated snapshot floor: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		INSERT INTO read_model_snapshots
		       (tenant_id, covered_seq, format_version, payload)
		VALUES ('a1140000-0000-4000-8000-000000000004', 22, $1,
		        '{"safe":"preserve-v23"}'::jsonb)`, store.SnapshotFormatVersion); err != nil {
		t.Fatalf("seed clean v23 snapshot behind malformed floor: %v", err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate over malformed validated snapshot floor: %v", err)
	}
	var rows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM read_model_snapshots
		  WHERE format_version = $1 AND payload = '{"safe":"preserve-v23"}'::jsonb`,
		store.SnapshotFormatVersion).Scan(&rows); err != nil {
		t.Fatalf("inspect preserved v23 snapshot: %v", err)
	}
	if rows != 1 {
		t.Fatalf("clean v23 rows after malformed-floor repair = %d, want 1", rows)
	}
	var constraintType, expression string
	var validated bool
	if err := s.SystemPool().QueryRow(ctx, `
		SELECT contype::text, convalidated,
		       regexp_replace(
		           replace(pg_get_expr(conbin, conrelid, true), '::integer', ''),
		           '[[:space:]()]', '', 'g'
		       )
		  FROM pg_constraint
		 WHERE conrelid = 'read_model_snapshots'::regclass
		   AND conname = $1`, floorConstraint).
		Scan(&constraintType, &validated, &expression); err != nil {
		t.Fatalf("inspect repaired snapshot floor: %v", err)
	}
	if constraintType != "c" || !validated || expression != "format_version>=23" {
		t.Fatalf("repaired snapshot floor = type:%q validated:%t expression:%q",
			constraintType, validated, expression)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		INSERT INTO read_model_snapshots
		       (tenant_id, covered_seq, format_version, payload)
		VALUES ('a1140000-0000-4000-8000-000000000005', 21, 21,
		        '{"unsafe":"rolling-v21"}'::jsonb)`); err == nil {
		t.Fatal("rolling v21 write succeeded after malformed-floor repair")
	}
}
