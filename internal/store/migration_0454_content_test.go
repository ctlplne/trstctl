// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// X3-L5: 0454 adds a pilot's observed-traffic requirement and window with
// constant defaults, and when a wave's traffic gate closed. Every pilot and
// wave recorded before it keeps its content and requires no observed
// traffic, so a running pilot advances on its probe exactly as it did.
func TestMigration0454KeepsPilotsAndRequiresNoObservedTraffic(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 454)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "45400000-0000-4000-8000-000000000001"
	const pilot = "45400000-0000-4000-8000-0000000000a1"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pqc_pilots
		        (tenant_id, id, name, authority_id, requested_by, status, wave_count, current_wave, halted_at_wave,
		         verdict_summary, created_at, updated_at)
		 VALUES ($1, $2, 'pre-0454 pilot', 'pq-ca', 'ops', 'running', 3, 2, '', 'Ready: all 1 targeted clients negotiated the PQ leaf.',
		         '2026-11-12T08:00:00Z', '2026-11-12T08:05:00Z')`, tenant, pilot); err != nil {
		t.Fatalf("seed a pre-0454 pilot: %v", err)
	}
	for i, status := range []string{"assessed", "probing", "pending"} {
		if _, err := tx.Exec(ctx, `INSERT INTO pqc_pilot_waves
			        (tenant_id, pilot_id, wave_index, name, targets, status, results, verdict, dispatched_at, assessed_at)
			 VALUES ($1, $2, $3, $4, '[{"target_id":"t","address":"a:443","fingerprint":"ff"}]'::jsonb, $5,
			         CASE WHEN $5 = 'assessed' THEN '[{"target_id":"t","outcome":"negotiated"}]'::jsonb END,
			         CASE WHEN $5 = 'assessed' THEN '{"ready":true}'::jsonb END,
			         CASE WHEN $5 <> 'pending' THEN '2026-11-12T08:01:00Z'::timestamptz END,
			         CASE WHEN $5 = 'assessed' THEN '2026-11-12T08:02:00Z'::timestamptz END)`,
			tenant, pilot, i+1, "wave "+status, status); err != nil {
			t.Fatalf("seed a pre-0454 %s wave: %v", status, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const pilots = `SELECT to_jsonb(p)::text FROM pqc_pilots p ORDER BY id`
	const waves = `SELECT to_jsonb(w)::text FROM pqc_pilot_waves w ORDER BY pilot_id, wave_index`
	pilotCount, pilotSum := checksumQuery(t, ctx, pool, pilots)
	waveCount, waveSum := checksumQuery(t, ctx, pool, waves)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	const keptPilots = `SELECT (to_jsonb(p) - 'require_observed_traffic' - 'observed_traffic_window_seconds')::text FROM pqc_pilots p ORDER BY id`
	const keptWaves = `SELECT (to_jsonb(w) - 'traffic_checked_at')::text FROM pqc_pilot_waves w ORDER BY pilot_id, wave_index`
	if n, after := checksumQuery(t, ctx, pool, keptPilots); pilotCount != 1 || n != pilotCount || after != pilotSum {
		t.Fatalf("0454 changed pilot content: %d/%s before, %d/%s after", pilotCount, pilotSum, n, after)
	}
	if n, after := checksumQuery(t, ctx, pool, keptWaves); waveCount != 3 || n != waveCount || after != waveSum {
		t.Fatalf("0454 changed wave content: %d/%s before, %d/%s after", waveCount, waveSum, n, after)
	}
	var gated, windows, checked int
	if err := pool.QueryRow(ctx, `SELECT
		    (SELECT count(*) FROM pqc_pilots WHERE require_observed_traffic),
		    (SELECT count(*) FROM pqc_pilots WHERE observed_traffic_window_seconds <> 0),
		    (SELECT count(*) FROM pqc_pilot_waves WHERE traffic_checked_at IS NOT NULL)`).Scan(&gated, &windows, &checked); err != nil {
		t.Fatal(err)
	}
	if gated != 0 || windows != 0 || checked != 0 {
		t.Fatalf("pre-0454 pilots gained a traffic gate: %d required, %d windows, %d checked waves", gated, windows, checked)
	}
	// The widened wave status accepts the gate's hold; the window check
	// refuses a window without the requirement.
	if _, err := pool.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,false)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE pqc_pilot_waves SET status = 'awaiting_traffic' WHERE tenant_id = $1 AND pilot_id = $2 AND wave_index = 2`, tenant, pilot); err != nil {
		t.Fatalf("awaiting_traffic refused after 0454: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE pqc_pilots SET observed_traffic_window_seconds = 60 WHERE tenant_id = $1 AND id = $2`, tenant, pilot); err == nil {
		t.Fatal("a traffic window without the requirement was accepted")
	}
}
