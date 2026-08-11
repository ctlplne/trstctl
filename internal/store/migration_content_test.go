// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// contentPrefixVersion is the historical schema point the SCHEMA-003 content test
// migrates TO before seeding. Every table the test populates (read-model owners +
// certificates, independent-state ssh_keys, sealed-blob secret_store + credentials,
// the outbox, and idempotency_keys) exists by this migration, so the rows can be
// seeded, then the REMAINING migrations (which include additive ALTERs to a
// populated outbox at 0032 and a populated certificates at 0036, plus a
// CONCURRENTLY-built index) are applied over real data.
const contentPrefixVersion = 31

var valueChangingMigrationContentHarnesses = map[int]bool{
	161: true,
	156: true,
	153: true,
	140: true,
	137: true,
	136: true,
	114: true,
	109: true,
	108: true,
	62:  true,
	72:  true,
	75:  true,
	77:  true,
	78:  true,
	79:  true,
	80:  true,
	81:  true,
	82:  true,
	83:  true,
	89:  true,
	90:  true,
	92:  true,
	94:  true,
	98:  true,
	100: true,
	101: true,
	102: true,
	105: true,
	106: true,
}

// seededContentColumns is the EXPLICIT, version-stable column projection used to
// checksum each seeded table. It deliberately names only the columns that exist at
// contentPrefixVersion, so a later additive ADD COLUMN (e.g. outbox.worker_id at
// 0032, certificates.issuance_idempotency_key at 0036) does NOT change the checksum:
// the test asserts the SEEDED content is preserved byte-for-byte across the upgrade,
// while still exercising the ALTER against populated rows. The ORDER BY makes the
// aggregate deterministic.
var seededContentColumns = map[string]struct {
	cols    string
	orderBy string
}{
	"owners":           {cols: "id::text, tenant_id::text, kind, name, email", orderBy: "id"},
	"certificates":     {cols: "id::text, tenant_id::text, COALESCE(owner_id::text,''), subject, array_to_string(sans, ','), fingerprint", orderBy: "id"},
	"ssh_keys":         {cols: "id::text, tenant_id::text, fingerprint, comment, location", orderBy: "id"},
	"secret_store":     {cols: "tenant_id::text, name, encode(sealed,'hex'), version", orderBy: "tenant_id, name"},
	"credentials":      {cols: "id::text, tenant_id::text, scope, ref, name, encode(sealed,'hex')", orderBy: "id"},
	"outbox":           {cols: "tenant_id::text, destination, encode(payload,'hex'), idempotency_key, status", orderBy: "id"},
	"idempotency_keys": {cols: "tenant_id::text, key, status, encode(COALESCE(result,''::bytea),'hex')", orderBy: "tenant_id, key"},
}

// TestMigrationsPreserveSeededContent is the SCHEMA-003 acceptance: existing
// migration tests cover ordering, locking, and online-DDL form, but NOT that
// populated before/after data CONTENT survives an upgrade. This test migrates a
// fresh database to a historical prefix, seeds representative multi-tenant rows
// across the read model, independent state, sealed-secret blobs, the outbox, and
// the idempotency ledger, captures per-table row counts AND deterministic content
// checksums, applies the REMAINING migrations (additive ALTERs over the now-
// populated certificates/outbox plus a CONCURRENTLY-built index), and asserts every
// seeded row count and content checksum is unchanged — i.e. no migration silently
// rewrote, dropped, or duplicated live tenant data, and a new column's default did
// not disturb existing values.
//
// It needs real embedded PostgreSQL (advisory locks, RLS, CONCURRENTLY). In a
// sandbox that cannot start embedded PostgreSQL it is skipped by the package's
// TestMain bootstrap, but it executes in CI.
func TestMigrationsPreserveSeededContent(t *testing.T) {
	ctx := context.Background()
	all := orderedMigrationFiles(t)
	var prefix, remaining []migrationFile
	for _, m := range all {
		if m.version <= contentPrefixVersion {
			prefix = append(prefix, m)
		} else {
			remaining = append(remaining, m)
		}
	}
	if len(prefix) == 0 || len(remaining) == 0 {
		t.Fatalf("expected a non-empty prefix and remaining set (prefix=%d remaining=%d)", len(prefix), len(remaining))
	}

	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)

	// 1) Apply the historical prefix.
	applyMigrationFiles(t, ctx, pool, prefix)

	// 2) Seed representative multi-tenant rows.
	seedMigrationContent(t, ctx, pool, tenantA)
	seedMigrationContent(t, ctx, pool, tenantB)

	// 3) Capture counts + content checksums BEFORE the remaining migrations.
	before := captureSeededContent(t, ctx, pool)
	for table, snap := range before {
		if snap.count == 0 {
			t.Fatalf("precondition: %s should have seeded rows before the upgrade", table)
		}
	}

	// 4) Apply the remaining migrations over the populated tables.
	applyMigrationFiles(t, ctx, pool, remaining)

	// 5) Capture AFTER and diff.
	after := captureSeededContent(t, ctx, pool)
	for table, b := range before {
		a, ok := after[table]
		if !ok {
			t.Errorf("%s vanished after the remaining migrations", table)
			continue
		}
		if a.count != b.count {
			t.Errorf("%s row count changed across migration: before=%d after=%d (data lost or duplicated)", table, b.count, a.count)
		}
		if a.checksum != b.checksum {
			t.Errorf("%s seeded content changed across migration: before=%s after=%s (a migration rewrote live data)", table, b.checksum, a.checksum)
		}
	}

	// 6) Additive columns must exist and carry their declared defaults on the
	// pre-existing rows (the ALTER applied to populated tables, not just empty ones).
	assertColumnDefault(t, ctx, pool, "outbox", "worker_id", "") // nullable add — NULL is fine, just must exist
	assertColumnDefault(t, ctx, pool, "outbox", "effect_lane", "")
	assertColumnDefault(t, ctx, pool, "remediation_playbook_runs", "request_binding", "")
	assertColumnDefault(t, ctx, pool, "remediation_playbook_runs", "initial_response", "")
	assertColumnDefault(t, ctx, pool, "remediation_playbook_runs", "terminal_reason", "")
	assertColumnDefault(t, ctx, pool, "certificates", "issuance_idempotency_key", "")
	assertColumnDefault(t, ctx, pool, "certificates", "issuance_request_binding", "")
	assertColumnDefault(t, ctx, pool, "certificates", "certificate_pem", "")
	assertColumnDefault(t, ctx, pool, "certificates", "issuance_response", "")
}

func TestMigration0157BuildsSchedulerScanIndexWithoutChangingPopulatedRows(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 157)
	if !target.noTx || target.name != "0157_secret_rotation_schedule_scan_index_no_transaction.sql" {
		t.Fatalf("migration 0157 classification = name:%q no_tx:%t, want the scheduler no-transaction index migration", target.name, target.noTx)
	}
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0157 content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	for index, tenantID := range []string{tenantA, tenantB} {
		for row := 1; row <= 3; row++ {
			id := fmt.Sprintf("15700000-0000-4000-800%d-%012d", index, row)
			if _, err := pool.Exec(ctx, `
				INSERT INTO secret_rotation_schedules
				       (id, tenant_id, name, provider, secret_key, old_ref,
				        interval_seconds, enabled, next_run_at, created_at, updated_at)
				VALUES ($1, $2, $3, 'connector:ci', $4, 'version:1', 3600,
				        $5, '2026-08-11T12:00:00Z',
				        '2026-08-11T11:00:00Z', '2026-08-11T11:00:00Z')`,
				id, tenantID, fmt.Sprintf("scan-index-%d-%d", index, row),
				fmt.Sprintf("rotation/index/%d/%d", index, row), row%2 == 1); err != nil {
				t.Fatalf("seed pre-0157 schedule %s: %v", id, err)
			}
		}
	}
	stable := `
		SELECT tenant_id::text, id::text, name, provider, secret_key, old_ref,
		       interval_seconds::text, enabled::text, next_run_at::text,
		       created_at::text, updated_at::text
		  FROM secret_rotation_schedules
		 ORDER BY tenant_id, id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 6 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0157 changed populated schedule content: before=%d/%s after=%d/%s", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
	assertIndexReady(t, ctx, pool, "secret_rotation_schedules_tenant_scan_idx")
	var definition string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_indexdef(indexrelid)
		   FROM pg_index
		  WHERE indexrelid = 'secret_rotation_schedules_tenant_scan_idx'::regclass`).Scan(&definition); err != nil {
		t.Fatalf("read 0157 scheduler index definition: %v", err)
	}
	normalizedDefinition := strings.ToLower(strings.Join(strings.Fields(definition), " "))
	if !strings.Contains(normalizedDefinition, "(tenant_id, id, next_run_at)") ||
		!strings.Contains(normalizedDefinition, "where enabled") {
		t.Fatalf("0157 scheduler index definition = %q, want UUID-ring order with enabled predicate", definition)
	}
}

func TestMigration0163BuildsTenantEffectiveLaneProcessingIndexWithoutChangingRowsAUD110(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 163)
	if !target.noTx || target.name != "0163_outbox_tenant_effective_lane_capacity.sql" {
		t.Fatalf("migration 0163 classification = name:%q no_tx:%t, want the tenant-lane no-transaction index migration", target.name, target.noTx)
	}
	assertMigrationUsesConcurrentIndex(t, 163,
		"CREATE INDEX CONCURRENTLY outbox_tenant_effective_lane_processing_idx")
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0163 content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	type fixture struct {
		tenantID string
		lane     string
		status   string
	}
	for row, item := range []fixture{
		{tenantID: tenantA, lane: "connector.deploy:shared", status: "processing"},
		{tenantID: tenantB, lane: "connector.deploy:shared", status: "processing"},
		{tenantID: tenantA, lane: "", status: "pending"},
		{tenantID: tenantB, lane: "", status: "pending"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO outbox
			       (tenant_id, destination, effect_lane, payload, idempotency_key,
			        status, attempts, next_attempt_at, created_at, worker_id, lease_until)
			VALUES ($1, 'connector.deploy', $2, $3, $4, $5, $6,
			        '2026-08-11T12:00:00Z'::timestamptz,
			        '2026-08-11T11:59:00Z'::timestamptz,
			        CASE WHEN $5 = 'processing' THEN 'aud110-worker' END,
			        CASE WHEN $5 = 'processing' THEN '2026-08-11T12:05:00Z'::timestamptz END)`,
			item.tenantID, item.lane, []byte(fmt.Sprintf("aud110-payload-%d", row)),
			fmt.Sprintf("aud110-migration-%d", row), item.status, row+1); err != nil {
			t.Fatalf("seed pre-0163 outbox row %d: %v", row, err)
		}
	}
	stable := `
		SELECT id::text, tenant_id::text, destination, effect_lane,
		       encode(payload, 'hex'), idempotency_key, status, attempts::text,
		       next_attempt_at::text, created_at::text, COALESCE(worker_id, ''),
		       COALESCE(lease_until::text, '')
		  FROM outbox
		 ORDER BY tenant_id, id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if beforeCount != 4 || afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0163 changed populated outbox content: before=%d/%s after=%d/%s",
			beforeCount, beforeChecksum, afterCount, afterChecksum)
	}

	assertIndexReady(t, ctx, pool, "outbox_tenant_effective_lane_processing_idx")
	assertIndexReady(t, ctx, pool, "outbox_effect_lane_processing_idx")
	var definition string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_indexdef(indexrelid)
		   FROM pg_index
		  WHERE indexrelid = 'outbox_tenant_effective_lane_processing_idx'::regclass`).Scan(&definition); err != nil {
		t.Fatalf("read 0163 tenant-lane index definition: %v", err)
	}
	normalizedDefinition := strings.ToLower(strings.Join(strings.Fields(definition), " "))
	for _, fragment := range []string{
		"tenant_id", "coalesce(nullif(effect_lane", "destination", "lease_until", "status = 'processing'",
	} {
		if !strings.Contains(normalizedDefinition, fragment) {
			t.Fatalf("0163 tenant-lane index definition = %q, missing %q", definition, fragment)
		}
	}
}

// TestMigrationDataContentBackfills is the SCHEMA-002 acceptance: migrations that
// write values, not just shapes, must prove their before/after transform over
// populated multi-tenant data at the exact N-1 -> N boundary.
func TestMigrationDataContentBackfills(t *testing.T) {
	t.Run("0153_secret_sync_target_order", testMigration0153SecretSyncTargetOrder)
	t.Run("0143_lifecycle_rotation_event_order", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 143)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		if _, err := pool.Exec(ctx, `
			INSERT INTO lifecycle_rotation_runs
			       (id, tenant_id, identity_id, outbox_id, status, trigger, reason,
			        predecessor_fingerprint, successor_fingerprint, rollback_ref,
			        error, idempotency_key, created_at, updated_at, completed_at)
			VALUES ('10000000-0000-4000-8000-000000000143',
			        '11111111-1111-1111-1111-111111111111',
			        '10000000-0000-4000-8000-000000000144', 143,
			        'succeeded', 'scheduled', 'legacy row', 'sha256:old',
			        'sha256:new', 'restore sha256:old', '', 'legacy:143',
			        '2026-08-10T12:00:00Z', '2026-08-10T12:01:00Z',
			        '2026-08-10T12:01:00Z')`); err != nil {
			t.Fatalf("seed pre-0143 lifecycle row: %v", err)
		}
		const stableProjection = `
			SELECT id::text, tenant_id::text, identity_id::text, outbox_id::text,
			       status, trigger, reason, predecessor_fingerprint,
			       successor_fingerprint, rollback_ref, error, idempotency_key,
			       created_at::text, updated_at::text, completed_at::text
			  FROM lifecycle_rotation_runs
			 ORDER BY tenant_id, id`
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stableProjection)
		applyMigrationFiles(t, ctx, pool, []migrationFile{target})
		afterCount, afterChecksum := checksumQuery(t, ctx, pool, stableProjection)
		if beforeCount != afterCount || beforeChecksum != afterChecksum {
			t.Fatalf("0143 rewrote legacy lifecycle evidence: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}

		var first, latest sql.NullInt64
		if err := pool.QueryRow(ctx, `
			SELECT first_event_sequence, latest_event_sequence
			  FROM lifecycle_rotation_runs
			 WHERE id = '10000000-0000-4000-8000-000000000143'`).Scan(&first, &latest); err != nil {
			t.Fatalf("read post-0143 sequence columns: %v", err)
		}
		if first.Valid || latest.Valid {
			t.Fatalf("legacy row sequence epoch = first:%v latest:%v, want NULL/NULL", first, latest)
		}
		if _, err := pool.Exec(ctx, `
			UPDATE lifecycle_rotation_runs
			   SET first_event_sequence = 144, latest_event_sequence = 143
			 WHERE id = '10000000-0000-4000-8000-000000000143'`); err == nil {
			t.Fatal("0143 accepted a latest event sequence before its first sequence")
		}
	})

	t.Run("0140_discovery_finding_replay_identity", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 140)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedDiscoveryFindingBackfillContent(t, ctx, pool)
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, discoveryFindingStableProjectionSQL())
		if beforeCount == 0 {
			t.Fatal("precondition: migration 0140 needs existing discovery findings")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})
		afterCount, afterChecksum := checksumQuery(t, ctx, pool, discoveryFindingStableProjectionSQL())
		if afterCount != beforeCount || afterChecksum != beforeChecksum {
			t.Fatalf("0140 changed existing discovery rows: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}
		var badAliases int
		if err := pool.QueryRow(ctx, `
			SELECT count(*)
			  FROM discovery_findings
			 WHERE cardinality(recorded_ids) <> 1 OR recorded_ids[1] <> id`).Scan(&badAliases); err != nil {
			t.Fatalf("read post-0140 aliases: %v", err)
		}
		if badAliases != 0 {
			t.Fatalf("0140 left %d existing findings without their exact payload-ID alias", badAliases)
		}
	})

	// 0098 adds the agent claim columns to the outbox — the busiest table in the
	// deployment, and one that is never empty in a running system. The property
	// that matters is not that the columns appear: it is that adding them leaves
	// every in-flight entry exactly as it was. An outbox row that was pending
	// before the migration must still be pending after it, with the same payload,
	// the same idempotency key and the same attempt count, and must land unclaimed
	// rather than looking like an agent has already taken it.
	t.Run("0098_outbox_agent_claims", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 98)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedOutboxClaimContent(t, ctx, pool)

		const entryProjection = `
			SELECT tenant_id::text, destination, encode(payload, 'hex'), idempotency_key,
			       status, attempts::text, coalesce(last_error, ''), delivered_at::text
			  FROM outbox
			 ORDER BY tenant_id, idempotency_key`
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, entryProjection)
		if beforeCount == 0 {
			t.Fatal("precondition: the content case needs seeded outbox entries to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, entryProjection)
		if afterCount != beforeCount || afterChecksum != beforeChecksum {
			t.Fatalf("0098 disturbed in-flight outbox entries: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}

		var claimed, badAttempts int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE claimed_by_agent_id IS NOT NULL OR claim_expires_at IS NOT NULL OR claim_completed_at IS NOT NULL),
			       count(*) FILTER (WHERE claim_attempts <> 0)
			  FROM outbox`).Scan(&claimed, &badAttempts); err != nil {
			t.Fatalf("read post-0098 claim columns: %v", err)
		}
		if claimed != 0 {
			t.Errorf("%d pre-existing entries came out of the migration looking claimed; every one must be claimable", claimed)
		}
		if badAttempts != 0 {
			t.Errorf("%d pre-existing entries came out with a non-zero claim count; none of them has ever been claimed", badAttempts)
		}

		// The lease invariant has to hold from the first row: an agent id without
		// an expiry is a claim nothing can ever reclaim.
		if _, err := pool.Exec(ctx, `
			UPDATE outbox SET claimed_by_agent_id = gen_random_uuid() WHERE true`); err == nil {
			t.Error("0098 accepted a claim with no lease expiry; outbox_claim_lease_present must reject it")
		}
	})

	// 0100 attaches the capability grant to bootstrap tokens (epic A2). Two things
	// have to hold across it, and only one of them is about shape. A token minted
	// before the migration must come out with an EMPTY grant — a pre-existing token
	// that silently acquired the relay role would be a real escalation handed to
	// whoever holds it — and the rest of the row, above all its single-use state,
	// must be untouched.
	t.Run("0100_agent_bootstrap_token_roles", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 100)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedBootstrapTokenContent(t, ctx, pool)

		const tokenProjection = `
			SELECT tenant_id::text, token_hash, allowed_identity,
			       (used_at IS NOT NULL)::text, expires_at::text
			  FROM agent_bootstrap_tokens
			 ORDER BY tenant_id, token_hash`
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, tokenProjection)
		if beforeCount == 0 {
			t.Fatal("precondition: the content case needs seeded bootstrap tokens to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, tokenProjection)
		if afterCount != beforeCount || afterChecksum != beforeChecksum {
			t.Fatalf("0100 disturbed existing bootstrap tokens: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}

		var granted int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM agent_bootstrap_tokens WHERE cardinality(granted_roles) > 0`).
			Scan(&granted); err != nil {
			t.Fatalf("read post-0100 grants: %v", err)
		}
		if granted != 0 {
			t.Errorf("%d pre-existing tokens came out of the migration carrying a capability grant; every one must come out ungranted", granted)
		}

		// The closed set is enforced by the database, not only by application
		// code: no repair script or psql session can leave a row carrying a role
		// the certificate stamper has no meaning for.
		if _, err := pool.Exec(ctx,
			`UPDATE agent_bootstrap_tokens SET granted_roles = ARRAY['admin']::text[] WHERE true`); err == nil {
			t.Error("0100 accepted an unknown agent role; agent_bootstrap_tokens_roles_known must reject it")
		}
	})

	// 0101 adds the fleet-view role projection. A pre-existing agent must come out
	// with NO roles rather than with host: the console shows an empty projection as
	// "not yet reported", and backfilling it to host would turn a gap in evidence
	// into a claim about an agent nobody has heard from.
	t.Run("0101_agent_roles", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 101)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedAgentRoleContent(t, ctx, pool)

		const agentProjection = `
			SELECT tenant_id::text, name, status, version, (last_seen_at IS NOT NULL)::text
			  FROM agents
			 ORDER BY tenant_id, name`
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, agentProjection)
		if beforeCount == 0 {
			t.Fatal("precondition: the content case needs seeded agents to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, agentProjection)
		if afterCount != beforeCount || afterChecksum != beforeChecksum {
			t.Fatalf("0101 disturbed existing agents: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}

		var projected int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM agents WHERE cardinality(roles) > 0`).Scan(&projected); err != nil {
			t.Fatalf("read post-0101 roles: %v", err)
		}
		if projected != 0 {
			t.Errorf("%d pre-existing agents came out with a projected role; every one must read as not-yet-reported until it heartbeats", projected)
		}
	})

	// 0102 stamps the per-row agent-role demand onto the outbox (epic A3). Every
	// row enqueued before it exists must come out with the EMPTY demand — the
	// value that means "kind-level rules alone", which is precisely the rule those
	// rows were enqueued under. A backfill that guessed a role from the payload
	// would relocate committed work; a backfill to 'control_plane' would strand
	// claimable rows. Empty is the only honest answer, and the whole row must
	// otherwise survive byte-identical.
	t.Run("0102_outbox_required_agent_role", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 102)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedOutboxClaimContent(t, ctx, pool)

		const entryProjection = `
			SELECT tenant_id::text, destination, encode(payload, 'hex'), idempotency_key,
			       status, attempts::text, coalesce(last_error, ''), delivered_at::text
			  FROM outbox
			 ORDER BY tenant_id, idempotency_key`
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, entryProjection)
		if beforeCount == 0 {
			t.Fatal("precondition: the content case needs seeded outbox entries to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, entryProjection)
		if afterCount != beforeCount || afterChecksum != beforeChecksum {
			t.Fatalf("0102 disturbed in-flight outbox entries: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}

		var demanded int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE required_agent_role <> ''`).Scan(&demanded); err != nil {
			t.Fatalf("read post-0102 demands: %v", err)
		}
		if demanded != 0 {
			t.Errorf("%d pre-existing rows came out of the migration carrying a role demand; every one must come out with kind-level rules alone", demanded)
		}

		// The vocabulary is closed at the database: no repair script can stamp a
		// demand the claim path has no meaning for.
		if _, err := pool.Exec(ctx,
			`UPDATE outbox SET required_agent_role = 'admin' WHERE true`); err == nil {
			t.Error("0102 accepted an unknown role demand; outbox_required_agent_role_known must reject it")
		}
	})

	// 0105 adds the observed-template column that makes drift real (epic F2).
	// The property that matters is the one the DEFAULT encodes: an existing row
	// must come out with an EMPTY observation, not a fabricated one. The drift
	// path skips rows with no observation and re-baselines quietly on the next
	// sweep; a backfilled '{}' that looked like a real template would make every
	// flag read false and report the whole estate as newly dangerous, which is
	// the false alarm this epic exists to avoid producing.
	t.Run("0105_adcs_template_observed", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 105)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedADCSPostureContent(t, ctx, pool)

		const projection = `
			SELECT tenant_id::text, domain, template, worst_severity,
			       finding_count::text, findings::text
			  FROM adcs_template_posture
			 ORDER BY tenant_id, domain, template`
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, projection)
		if beforeCount == 0 {
			t.Fatal("precondition: the content case needs seeded posture rows to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, projection)
		if afterCount != beforeCount || afterChecksum != beforeChecksum {
			t.Fatalf("0105 disturbed existing posture rows: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}

		var fabricated int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM adcs_template_posture WHERE observed_template <> '{}'::jsonb`).
			Scan(&fabricated); err != nil {
			t.Fatalf("read post-0105 observations: %v", err)
		}
		if fabricated != 0 {
			t.Errorf("%d pre-existing rows came out carrying a fabricated observation; every one must come out empty so the next sweep re-baselines instead of alarming", fabricated)
		}
	})

	// 0106 adds per-certificate key custody (epic B5). The property that matters
	// is what the DEFAULT encodes: every pre-existing certificate must come out
	// UNRECORDED. Backfilling any origin would be inventing an audit claim — the
	// whole point of recording custody per certificate is that it reflects what
	// the issuing code did, and nobody observed the issuance of a row that
	// predates the column. Unrecorded is the only honest value, and the console
	// renders it as unknown rather than as reassurance.
	// 0108 adds declared segments and per-certificate provenance (epic C3). The
	// property that matters is the same one 0106 protects, for a sharper
	// reason: provenance is a claim that something OBSERVED a certificate, and
	// a migration cannot observe anything. Every pre-existing row must come out
	// with no observation at all, because none was made — a default that
	// stamped "seen now" on the whole inventory would turn a migration into
	// evidence of a scan that never ran.
	t.Run("0108_discovery_segments_and_provenance", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 108)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedMigrationContent(t, ctx, pool, tenantA)
		seedMigrationContent(t, ctx, pool, tenantB)

		const projection = `
			SELECT tenant_id::text, subject, fingerprint
			  FROM certificates
			 ORDER BY tenant_id, fingerprint`
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, projection)
		if beforeCount == 0 {
			t.Fatal("precondition: the content case needs seeded certificates to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, projection)
		if afterCount != beforeCount || afterChecksum != beforeChecksum {
			t.Fatalf("0108 disturbed existing certificates: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}

		var observed int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM certificates
			  WHERE observed_by <> '' OR observed_kind <> '' OR last_seen_at IS NOT NULL`).
			Scan(&observed); err != nil {
			t.Fatalf("read post-0108 provenance: %v", err)
		}
		if observed != 0 {
			t.Errorf("%d pre-existing certificates came out claiming an observation nobody made; "+
				"a migration cannot observe a certificate, and stamping one would make a stale "+
				"inventory read as freshly verified", observed)
		}

		// And the segment table starts empty: coverage must open at "nothing
		// declared", not at a fabricated segment nobody owns.
		var segments int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM discovery_segments`).Scan(&segments); err != nil {
			t.Fatalf("read post-0108 segments: %v", err)
		}
		if segments != 0 {
			t.Errorf("0108 invented %d declared segments", segments)
		}
	})

	// 0109 adds upstream-DV consent (epic B7). The property is consent, not
	// shape: every provider config that already exists was created so trstctl
	// could VERIFY a challenge somebody else published. None of them agreed
	// that trstctl may PUBLISH into that zone whenever an external CA asks. A
	// migration that defaulted the column true would grant that silently,
	// across every zone an operator ever gave us credentials for.
	// B3: existing agents must come out of 0114 as "never reported", NOT as
	// "reported that they are not serving". The two render identically under a
	// boolean and call for opposite responses — an upgrade versus a config
	// change — so the whole value of the three-state surface rests on the
	// migration leaving reported_at NULL rather than stamping a time.
	t.Run("0114_agent_workload_api_posture", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 114)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx,
				`INSERT INTO agents (id, tenant_id, name, status, version, last_seen_at)
				 VALUES (gen_random_uuid(), $1, $2, 'active', '1.0.0', now())`,
				tenant, "host-"+tenant); err != nil {
				t.Fatalf("seed agent for %s: %v", tenant, err)
			}
		}

		var before int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&before); err != nil {
			t.Fatalf("count seeded agents: %v", err)
		}
		if before == 0 {
			t.Fatal("precondition: the content case needs seeded agents to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		var after, reported, serving int
		if err := pool.QueryRow(ctx,
			`SELECT count(*),
			        count(*) FILTER (WHERE workload_api_reported_at IS NOT NULL),
			        count(*) FILTER (WHERE workload_api_served)
			   FROM agents`).Scan(&after, &reported, &serving); err != nil {
			t.Fatalf("read post-0114 agents: %v", err)
		}
		if after != before {
			t.Fatalf("0114 changed the agent count: %d before, %d after", before, after)
		}
		if reported != 0 {
			t.Errorf("%d existing agents came out of the migration claiming to have reported "+
				"Workload API state they never sent; the console would tell an operator to "+
				"change a flag on a host whose agent is simply too old to answer", reported)
		}
		if serving != 0 {
			t.Errorf("%d existing agents came out marked as serving a Workload API socket they "+
				"were never asked to serve", serving)
		}
	})

	t.Run("0109_acme_dns01_upstream_dv", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 109)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx,
				`INSERT INTO acme_dns01_provider_configs
				     (id, tenant_id, name, provider, zone, credential_refs, config,
				      allowed_methods, allow_wildcards, created_at, updated_at)
				 VALUES (gen_random_uuid(), $1, $2, 'route53', 'example.test',
				         '{}'::jsonb, '{}'::jsonb, ARRAY['dns-01'], true, now(), now())`,
				tenant, "seeded-"+tenant); err != nil {
				t.Fatalf("seed provider config for %s: %v", tenant, err)
			}
		}

		var before int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM acme_dns01_provider_configs`).Scan(&before); err != nil {
			t.Fatalf("count seeded configs: %v", err)
		}
		if before == 0 {
			t.Fatal("precondition: the content case needs seeded provider configs to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		var after, consented int
		if err := pool.QueryRow(ctx,
			`SELECT count(*), count(*) FILTER (WHERE allow_upstream_dv)
			   FROM acme_dns01_provider_configs`).Scan(&after, &consented); err != nil {
			t.Fatalf("read post-0109 configs: %v", err)
		}
		if after != before {
			t.Fatalf("0109 changed the config count: %d before, %d after", before, after)
		}
		if consented != 0 {
			t.Errorf("%d existing provider configs came out consenting to upstream domain "+
				"validation nobody agreed to; a migration cannot grant permission to publish "+
				"into an operator's DNS zone on an external CA's behalf", consented)
		}
	})

	// 0110 adds the upstream authorization read model (epic B7). The property
	// is the same one 0108 protects for observation, sharpened: a migration
	// cannot invent validation history. The table's whole purpose is to say
	// when an identifier last actually PROVED control, and the tempting
	// convenience — backfill a row per provider config, or per certificate,
	// stamped "validated at migration time" — would manufacture exactly the
	// evidence an operator is meant to check. A deployment upgrading into this
	// table has never validated anything upstream, and must come out saying so.
	t.Run("0110_acme_upstream_authorizations", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 110)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		// Seed the things a backfill would be tempted to derive rows FROM:
		// existing provider configs, and existing certificates.
		for _, tenant := range []string{tenantA, tenantB} {
			if _, err := pool.Exec(ctx,
				`INSERT INTO acme_dns01_provider_configs
				     (id, tenant_id, name, provider, zone, credential_refs, config,
				      allowed_methods, allow_wildcards, allow_upstream_dv, created_at, updated_at)
				 VALUES (gen_random_uuid(), $1, $2, 'route53', 'example.test',
				         '{}'::jsonb, '{}'::jsonb, ARRAY['dns-01'], true, true, now(), now())`,
				tenant, "seeded-"+tenant); err != nil {
				t.Fatalf("seed provider config for %s: %v", tenant, err)
			}
			seedMigrationContent(t, ctx, pool, tenant)
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		var rows int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM acme_upstream_authorizations`).Scan(&rows); err != nil {
			t.Fatalf("read post-0110 authorizations: %v", err)
		}
		if rows != 0 {
			t.Errorf("%d authorization rows exist immediately after the migration; a schema "+
				"change cannot witness a domain-validation challenge, and a backfilled row "+
				"would report control this deployment has never proved", rows)
		}
	})

	t.Run("0106_certificate_key_custody", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 106)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedMigrationContent(t, ctx, pool, tenantA)
		seedMigrationContent(t, ctx, pool, tenantB)

		const projection = `
			SELECT tenant_id::text, subject, fingerprint
			  FROM certificates
			 ORDER BY tenant_id, fingerprint`
		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, projection)
		if beforeCount == 0 {
			t.Fatal("precondition: the content case needs seeded certificates to protect")
		}

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, projection)
		if afterCount != beforeCount || afterChecksum != beforeChecksum {
			t.Fatalf("0106 disturbed existing certificates: %d/%s before, %d/%s after",
				beforeCount, beforeChecksum, afterCount, afterChecksum)
		}

		var claimed int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM certificates
			  WHERE key_origin <> '' OR key_storage <> '' OR key_exportable <> ''`).
			Scan(&claimed); err != nil {
			t.Fatalf("read post-0106 custody: %v", err)
		}
		if claimed != 0 {
			t.Errorf("%d pre-existing certificates came out carrying a custody claim nobody observed; every one must come out unrecorded", claimed)
		}

		// The vocabulary is closed at the database, because a custody claim is
		// evidence an auditor reads.
		if _, err := pool.Exec(ctx,
			`UPDATE certificates SET key_origin = 'somewhere' WHERE true`); err == nil {
			t.Error("0106 accepted an unknown key origin; certificates_key_origin_known must reject it")
		}
	})

	t.Run("0046_secret_store_versions", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 46)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedSecretStoreBackfillContent(t, ctx, pool)

		var versionsTableExists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('secret_store_versions') IS NOT NULL`).Scan(&versionsTableExists); err != nil {
			t.Fatalf("check pre-0046 table existence: %v", err)
		}
		if versionsTableExists {
			t.Fatal("precondition: secret_store_versions must not exist before migration 0046")
		}

		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, `
			SELECT tenant_id::text, name, version::text, encode(sealed, 'hex'), updated_at::text
			  FROM secret_store
			 ORDER BY tenant_id, name, version`)

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, `
			SELECT tenant_id::text, name, version::text, encode(sealed, 'hex'), written_at::text
			  FROM secret_store_versions
			 ORDER BY tenant_id, name, version`)
		if afterCount != beforeCount {
			t.Fatalf("secret_store_versions backfill count mismatch: before=%d after=%d", beforeCount, afterCount)
		}
		if afterChecksum != beforeChecksum {
			t.Fatalf("secret_store_versions backfill changed values: before=%s after=%s", beforeChecksum, afterChecksum)
		}
	})

	t.Run("0051_discovery_finding_triage", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 51)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedDiscoveryFindingBackfillContent(t, ctx, pool)

		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, discoveryFindingStableProjectionSQL())

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, discoveryFindingStableProjectionSQL())
		if afterCount != beforeCount {
			t.Fatalf("discovery_findings count changed across 0051: before=%d after=%d", beforeCount, afterCount)
		}
		if afterChecksum != beforeChecksum {
			t.Fatalf("discovery_findings existing values changed across 0051: before=%s after=%s", beforeChecksum, afterChecksum)
		}

		var count int
		var statusOK, managedIDOK, actorOK, reasonOK, triagedAtOK bool
		if err := pool.QueryRow(ctx, `
			SELECT count(*),
			       bool_and(triage_status = 'unmanaged'),
			       bool_and(managed_identity_id IS NULL),
			       bool_and(triage_actor = ''),
			       bool_and(triage_reason = ''),
			       bool_and(triaged_at IS NULL)
			  FROM discovery_findings`).Scan(&count, &statusOK, &managedIDOK, &actorOK, &reasonOK, &triagedAtOK); err != nil {
			t.Fatalf("query 0051 default-filled columns: %v", err)
		}
		if count != beforeCount || !statusOK || !managedIDOK || !actorOK || !reasonOK || !triagedAtOK {
			t.Fatalf("0051 defaults mismatch: count=%d want=%d status=%t managed_id=%t actor=%t reason=%t triaged_at=%t",
				count, beforeCount, statusOK, managedIDOK, actorOK, reasonOK, triagedAtOK)
		}

		var indexExists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('discovery_findings_triage_status_idx') IS NOT NULL`).Scan(&indexExists); err != nil {
			t.Fatalf("check 0051 triage index: %v", err)
		}
		if !indexExists {
			t.Fatal("expected discovery_findings_triage_status_idx after migration 0051")
		}
	})

	t.Run("0062_notification_routing_policy_metadata", func(t *testing.T) {
		ctx := context.Background()
		prefix, target := splitMigrationsAtVersion(t, 62)
		dsn := createFreshMigrationDatabase(t)
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect fresh content database: %v", err)
		}
		t.Cleanup(pool.Close)

		applyMigrationFiles(t, ctx, pool, prefix)
		seedNotificationRoutingPolicyMetadataContent(t, ctx, pool)

		beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, notificationRoutingPolicyStableProjectionSQL())

		applyMigrationFiles(t, ctx, pool, []migrationFile{target})

		afterCount, afterChecksum := checksumQuery(t, ctx, pool, notificationRoutingPolicyStableProjectionSQL())
		if afterCount != beforeCount {
			t.Fatalf("notification_routing_policies count changed across 0062: before=%d after=%d", beforeCount, afterCount)
		}
		if afterChecksum != beforeChecksum {
			t.Fatalf("notification_routing_policies existing values changed across 0062: before=%s after=%s", beforeChecksum, afterChecksum)
		}

		var count int
		var ownerRefOK, ownerEmailOK, digestIntervalOK, digestTimezoneOK bool
		if err := pool.QueryRow(ctx, `
			SELECT count(*),
			       bool_and(owner_ref = ''),
			       bool_and(owner_email = ''),
			       bool_and(digest_interval_seconds = 86400),
			       bool_and(digest_timezone = 'UTC')
			  FROM notification_routing_policies`).Scan(&count, &ownerRefOK, &ownerEmailOK, &digestIntervalOK, &digestTimezoneOK); err != nil {
			t.Fatalf("query 0062 default-filled columns: %v", err)
		}
		if count != beforeCount || !ownerRefOK || !ownerEmailOK || !digestIntervalOK || !digestTimezoneOK {
			t.Fatalf("0062 defaults mismatch: count=%d want=%d owner_ref=%t owner_email=%t digest_interval=%t digest_timezone=%t",
				count, beforeCount, ownerRefOK, ownerEmailOK, digestIntervalOK, digestTimezoneOK)
		}
	})

	t.Run("0072_connector_target_revision_backfill", testMigration0072ConnectorTargetRevisionBackfill)
	t.Run("0075_dynamic_secret_preparation_default", testMigration0075DynamicSecretPreparationDefault)
	t.Run("0077_idempotency_request_binding_default", testMigration0077IdempotencyRequestBindingDefault)
	t.Run("0078_dynamic_secret_request_binding_default", testMigration0078DynamicSecretRequestBindingDefault)
	t.Run("0079_managed_key_request_binding_default", testMigration0079ManagedKeyRequestBindingDefault)
	t.Run("0080_external_ca_request_binding_defaults", testMigration0080ExternalCARequestBindingDefaults)
	t.Run("0081_dynamic_secret_command_backfill", testMigration0081DynamicSecretCommandBackfill)
	t.Run("0082_connector_right_size_operation_defaults", testMigration0082ConnectorRightSizeOperationDefaults)
	t.Run("0083_outbox_effect_lane_default", testMigration0083OutboxEffectLaneDefault)
	t.Run("0089_gcp_workload_identity_default", testMigration0089GCPWorkloadIdentityDefault)
	t.Run("0090_azure_workload_identity_defaults", testMigration0090AzureWorkloadIdentityDefaults)
	t.Run("0092_idempotency_result_codec_classification", testMigration0092IdempotencyResultCodecClassification)
	t.Run("0094_crypto_asset_projection_order_defaults", testMigration0094CryptoAssetProjectionOrderDefaults)
	t.Run("0136_fleet_reissuance_cursor_defaults", testMigration0136FleetReissuanceCursorDefaults)
	t.Run("0137_relay_external_pollers", testMigration0137RelayExternalPollers)
}

func testMigration0153SecretSyncTargetOrder(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 153)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0153 content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	type row struct {
		tenant, id, target, remoteKey, status string
	}
	rows := []row{
		{tenantA, "sync-a-ci-first", "ci", "/TOKEN/", "failed"},
		{tenantA, "sync-a-ci-second", "ci", "TOKEN", "failed"},
		{tenantA, "sync-a-vault", "vault", "TOKEN", "failed"},
		{tenantB, "sync-b-ci", "ci", "TOKEN", "failed"},
	}
	outboxIDs := make(map[string]int64, len(rows))
	for index, candidate := range rows {
		var outboxID int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO outbox
			       (tenant_id, destination, effect_lane, payload, idempotency_key,
			        status, attempts, last_error)
			VALUES ($1, $2, $3, $4, $5, $6, 1, 'legacy receiver failure')
			RETURNING id`, candidate.tenant, "secret.sync."+candidate.target,
			"secret.sync:"+candidate.target,
			migration0153SecretSyncPayload(candidate.id, candidate.target, candidate.remoteKey, "binding:"+candidate.id),
			"migration-0153:"+candidate.id, candidate.status).Scan(&outboxID); err != nil {
			t.Fatalf("seed 0153 outbox %s: %v", candidate.id, err)
		}
		outboxIDs[candidate.id] = outboxID
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_sync_jobs
			       (tenant_id, id, secret_name, secret_version, target, remote_key,
			        value_digest, status, outbox_id, attempts, last_error,
			        idempotency_key, request_binding,
			        requested_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1,
			        'legacy receiver failure', $10, $11,
			        '2026-08-10T12:00:00Z', '2026-08-10T12:00:00Z')`,
			candidate.tenant, candidate.id, "migration/secret", index+1,
			candidate.target, candidate.remoteKey, strings.Repeat("a", 64), candidate.status,
			outboxID, "migration-0153:"+candidate.id, "binding:"+candidate.id); err != nil {
			t.Fatalf("seed 0153 job %s: %v", candidate.id, err)
		}
	}

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	wantOrders := map[string]int64{
		"sync-a-ci-first": -1, "sync-a-ci-second": -2,
		"sync-a-vault": -1, "sync-b-ci": -1,
	}
	for id, want := range wantOrders {
		var got int64
		if err := pool.QueryRow(ctx,
			`SELECT target_order FROM secret_sync_jobs WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatalf("read 0153 target order %s: %v", id, err)
		}
		if got != want {
			t.Fatalf("0153 target order %s=%d, want %d", id, got, want)
		}
		var outboxOrder int64
		var fromEvent bool
		var effectState, failureDetail string
		var receiverStarts int64
		var failureAttempts int
		if err := pool.QueryRow(ctx,
			`SELECT secret_sync_target_order, secret_sync_order_from_event,
			        secret_sync_receiver_effect_state, secret_sync_receiver_io_starts,
			        secret_sync_failure_detail, secret_sync_failure_attempts
			   FROM outbox WHERE id = $1`, outboxIDs[id]).Scan(
			&outboxOrder, &fromEvent, &effectState, &receiverStarts, &failureDetail, &failureAttempts); err != nil {
			t.Fatalf("read 0153 outbox order %s: %v", id, err)
		}
		if outboxOrder != want || fromEvent || effectState != "effect_possible" ||
			receiverStarts != 1 || failureDetail != "" || failureAttempts != 0 {
			t.Fatalf("0153 outbox authority %s=(order:%d,event:%t,state:%q,starts:%d,detail:%q,failure-attempts:%d), want conservative legacy failed ambiguity",
				id, outboxOrder, fromEvent, effectState, receiverStarts, failureDetail, failureAttempts)
		}
		var receiptType, receiptDigest string
		var receiptSequence int64
		var receiptFromEvent bool
		if err := pool.QueryRow(ctx, `
			SELECT terminal_event_type, terminal_event_sequence,
			       terminal_event_digest, terminal_event_from_event
			  FROM secret_sync_jobs WHERE id = $1`, id).Scan(
			&receiptType, &receiptSequence, &receiptDigest, &receiptFromEvent); err != nil {
			t.Fatalf("read 0153 terminal receipt %s: %v", id, err)
		}
		if receiptType != "legacy.secret.sync.failed" || receiptSequence != -want ||
			len(receiptDigest) != 64 || receiptFromEvent {
			t.Fatalf("0153 terminal receipt %s=(%q,%d,%q,event:%t), want synthetic legacy receipt",
				id, receiptType, receiptSequence, receiptDigest, receiptFromEvent)
		}
	}

	var uniqueReady, rlsEnabled, rlsForced bool
	if err := pool.QueryRow(ctx, `
		SELECT i.indisunique AND i.indisready AND i.indisvalid,
		       c.relrowsecurity, c.relforcerowsecurity
		  FROM pg_class c
		  JOIN pg_index i ON i.indrelid = c.oid
		  JOIN pg_class idx ON idx.oid = i.indexrelid
		 WHERE c.relname = 'secret_sync_jobs'
		   AND idx.relname = 'secret_sync_jobs_target_order_idx'`).Scan(&uniqueReady, &rlsEnabled, &rlsForced); err != nil {
		t.Fatalf("inspect 0153 index/RLS: %v", err)
	}
	if !uniqueReady || !rlsEnabled || !rlsForced {
		t.Fatalf("0153 index/RLS unique_ready=%t enabled=%t forced=%t", uniqueReady, rlsEnabled, rlsForced)
	}
	assertIndexReady(t, ctx, pool, "outbox_secret_sync_idempotency_idx")

	// An old writer omits the event order and now fails closed. A new writer copies
	// one exact AN-2 sequence into both halves; direct rewrites are rejected.
	if _, err := pool.Exec(ctx, `
		INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		VALUES ($1, 'secret.sync.ci', 'secret.sync:ci', $2, 'migration-0153:old-writer')`,
		tenantA, []byte(`{"sealed":"old"}`)); err == nil {
		t.Fatal("0153 accepted an old secret-sync writer without event target order")
	}
	spoofRestoreTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spoofRestoreTx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := spoofRestoreTx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := spoofRestoreTx.Exec(ctx, `SET LOCAL trstctl.postgres_state_restore = 'true'`); err != nil {
		t.Fatal(err)
	}
	_, spoofRestoreErr := spoofRestoreTx.Exec(ctx, `
		INSERT INTO outbox
		       (tenant_id, destination, effect_lane, payload, idempotency_key,
		        secret_sync_target_order, secret_sync_order_from_event,
		        secret_sync_receiver_effect_state, secret_sync_receiver_io_starts)
		VALUES ($1, 'secret.sync.ci', 'secret.sync:ci', $2,
		        'migration-0153:spoofed-restore', 99, true, 'effect_possible', 2)`,
		tenantA, migration0153SecretSyncPayload("sync-a-ci-spoofed-restore", "ci", "SPOOF", "binding:spoofed-restore"))
	_ = spoofRestoreTx.Rollback(ctx)
	if spoofRestoreErr == nil || !strings.Contains(spoofRestoreErr.Error(), "new secret-sync outbox rows require a positive AN-2 event order") {
		t.Fatalf("0153 application-role restore-marker spoof error=%v, want receiver-authority insert rejection", spoofRestoreErr)
	}
	var thirdOutbox int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO outbox
		       (tenant_id, destination, effect_lane, payload, idempotency_key,
		        secret_sync_target_order, secret_sync_order_from_event)
		VALUES ($1, 'secret.sync.fresh', 'secret.sync:fresh', $2, 'migration-0153:third', 100, true)
		RETURNING id`, tenantA,
		migration0153SecretSyncPayload("sync-a-ci-third", "fresh", "OTHER", "binding:third")).Scan(&thirdOutbox); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO secret_sync_jobs
		       (tenant_id, tenant_epoch, id, secret_name, secret_version, target, remote_key,
		        value_digest, status, outbox_id, target_order, idempotency_key, request_binding,
		        requested_at, updated_at)
		VALUES ($1, (SELECT epoch_id::text FROM application_secret_tenant_epochs WHERE tenant_id = $1),
		        'sync-a-ci-third', 'migration/secret', 3, 'fresh', 'OTHER', $2,
		        'pending', $3, 100, 'migration-0153:third', 'binding:third', now(), now())`,
		tenantA, strings.Repeat("b", 64), thirdOutbox); err != nil {
		t.Fatalf("old-writer insert after 0153: %v", err)
	}
	var thirdOrder int64
	if err := pool.QueryRow(ctx,
		`SELECT target_order FROM secret_sync_jobs WHERE tenant_id = $1 AND id = 'sync-a-ci-third'`, tenantA).Scan(&thirdOrder); err != nil {
		t.Fatal(err)
	}
	if thirdOrder != 100 {
		t.Fatalf("event target order=%d, want 100", thirdOrder)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE secret_sync_jobs SET target_order = 99 WHERE tenant_id = $1 AND id = 'sync-a-ci-third'`, tenantA); err == nil {
		t.Fatal("0153 allowed target-order mutation")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE outbox SET secret_sync_target_order = 99 WHERE id = $1`, thirdOutbox); err == nil {
		t.Fatal("0153 allowed retained outbox target-order mutation")
	}
	var fourthOutbox int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO outbox
		       (tenant_id, destination, effect_lane, payload, idempotency_key,
		        secret_sync_target_order, secret_sync_order_from_event)
		VALUES ($1, 'secret.sync.fresh', 'secret.sync:fresh', $2, 'migration-0153:fourth', 101, true)
		RETURNING id`, tenantA,
		migration0153SecretSyncPayload("sync-a-ci-fourth", "fresh", "FINAL", "binding:fourth")).Scan(&fourthOutbox); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO secret_sync_jobs
		       (tenant_id, tenant_epoch, id, secret_name, secret_version, target, remote_key,
		        value_digest, status, outbox_id, target_order, idempotency_key,
		        request_binding, requested_at, updated_at)
		VALUES ($1, (SELECT epoch_id::text FROM application_secret_tenant_epochs WHERE tenant_id = $1),
		        'sync-a-ci-fourth', 'migration/secret', 4, 'fresh', 'FINAL', $2,
		        'pending', $3, 101, 'migration-0153:fourth', 'binding:fourth', now(), now())`,
		tenantA, strings.Repeat("c", 64), fourthOutbox); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE projection_checkpoint SET applied_seq = 101, updated_at = now() WHERE id = 1`); err != nil {
		t.Fatal(err)
	}

	// This is the old worker's claim shape: it knows nothing about target_order.
	// The DB trigger skips a successor while its predecessor is pending, but lets
	// another target progress.
	claim := func(id int64) int64 {
		t.Helper()
		tag, err := pool.Exec(ctx,
			`UPDATE outbox SET status = 'processing', worker_id = 'old-worker', lease_until = now() + interval '1 minute'
			  WHERE id = $1 AND status = 'pending'`, id)
		if err != nil {
			t.Fatalf("old-style claim %d: %v", id, err)
		}
		return tag.RowsAffected()
	}
	if got := claim(fourthOutbox); got != 0 {
		t.Fatalf("old worker claimed blocked same-target successor: rows=%d", got)
	}
	var blockedAttempts int
	if err := pool.QueryRow(ctx, `SELECT attempts FROM outbox WHERE id = $1`, fourthOutbox).Scan(&blockedAttempts); err != nil {
		t.Fatal(err)
	}
	if blockedAttempts != 0 {
		t.Fatalf("blocked old-style claim consumed attempts=%d, want 0", blockedAttempts)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE outbox SET status = 'failed' WHERE id = $1`, thirdOutbox); err == nil {
		t.Fatal("0153 retired a pending outbox before its domain job became terminal")
	}
	forgedTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forgedTx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := forgedTx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	_, forgedErr := forgedTx.Exec(ctx, `
		UPDATE secret_sync_jobs
		   SET status = 'failed', attempts = 1, last_error = 'forged', updated_at = now(),
		       terminal_event_id = 'secret-sync-forged',
		       terminal_event_type = 'secret.sync.failed', terminal_event_sequence = 999,
		       terminal_event_digest = $2, terminal_event_from_event = true
		 WHERE tenant_id = $1 AND id = 'sync-a-ci-third'`, tenantA, strings.Repeat("e", 64))
	_ = forgedTx.Rollback(ctx)
	if forgedErr == nil {
		t.Fatal("0153 let the application role forge terminal event evidence with a custom tenant GUC")
	}
	authorityTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorityTx.Exec(ctx, `
		UPDATE outbox
		   SET secret_sync_receiver_effect_state = 'effect_possible',
		       secret_sync_receiver_io_starts = 1
		 WHERE id = $1`, thirdOutbox); err != nil {
		t.Fatal(err)
	}
	if _, err := authorityTx.Exec(ctx, `
		UPDATE outbox SET secret_sync_receiver_io_starts = 2 WHERE id = $1`, thirdOutbox); err != nil {
		t.Fatal(err)
	}
	if _, err := authorityTx.Exec(ctx, `
		UPDATE outbox
		   SET secret_sync_receiver_effect_state = 'failure_authorized',
		       secret_sync_failure_detail = 'unsafe multi-generation failure',
		       secret_sync_failure_attempts = 2
		 WHERE id = $1`, thirdOutbox); err == nil {
		t.Fatal("0153 allowed effect_possible count 2 to authorize failure")
	}
	_ = authorityTx.Rollback(ctx)
	if _, err := pool.Exec(ctx, `
		UPDATE outbox
		   SET secret_sync_receiver_effect_state = 'failure_authorized',
		       secret_sync_failure_detail = 'terminal fixture',
		       secret_sync_failure_attempts = 1
		 WHERE id = $1`, thirdOutbox); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE secret_sync_jobs
		    SET status = 'failed', attempts = 1, last_error = 'terminal fixture',
		        updated_at = now(),
		        terminal_event_id = 'secret-sync-failed-fixture',
		        terminal_event_type = 'secret.sync.failed',
		        terminal_event_sequence = 1000,
		        terminal_event_digest = $2,
		        terminal_event_from_event = true
		  WHERE tenant_id = $1 AND id = 'sync-a-ci-third'`, tenantA, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE outbox SET status = 'failed' WHERE id = $1`, thirdOutbox); err != nil {
		t.Fatal(err)
	}
	if got := claim(fourthOutbox); got != 1 {
		t.Fatalf("terminal predecessor did not release successor: rows=%d", got)
	}
	for _, changedStatus := range []string{"pending", "processing", "delivered"} {
		if _, err := pool.Exec(ctx,
			`UPDATE outbox SET status = $2 WHERE id = $1`, thirdOutbox, changedStatus); err == nil {
			t.Fatalf("0153 allowed terminal secret-sync outbox status change to %s", changedStatus)
		}
	}
	for _, changedStatus := range []string{"pending", "delivered"} {
		if _, err := pool.Exec(ctx,
			`UPDATE secret_sync_jobs SET status = $2 WHERE tenant_id = $1 AND id = 'sync-a-ci-first'`,
			tenantA, changedStatus); err == nil {
			t.Fatalf("0153 allowed failed secret-sync job status change to %s", changedStatus)
		}
	}
	if _, err := pool.Exec(ctx,
		`UPDATE secret_sync_jobs SET status = 'failed' WHERE tenant_id = $1 AND id = 'sync-a-ci-first'`, tenantA); err != nil {
		t.Fatalf("0153 rejected same-status failed job update: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE secret_sync_jobs SET attempts = attempts + 1
		  WHERE tenant_id = $1 AND id = 'sync-a-ci-first'`, tenantA); err == nil {
		t.Fatal("0153 allowed terminal secret-sync evidence mutation")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE secret_sync_jobs SET terminal_event_digest = $2
		  WHERE tenant_id = $1 AND id = 'sync-a-ci-first'`, tenantA, strings.Repeat("0", 64)); err == nil {
		t.Fatal("0153 allowed terminal secret-sync receipt mutation")
	}
}

func migration0153SecretSyncPayload(id, target, key, binding string) []byte {
	return []byte(fmt.Sprintf(
		`{"id":%q,"key":%q,"target":%q,"request_binding":%q,"sealed":"c2VhbGVk"}`,
		id, key, target, binding,
	))
}

func TestMigration0153RefusesPreexistingSecretSyncClaim(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 153)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0153 claim database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	if _, err := pool.Exec(ctx, `
		INSERT INTO outbox
		       (tenant_id, destination, payload, idempotency_key, status, worker_id, lease_until)
		VALUES ($1, 'secret.sync.ci', $2, 'migration-0153-processing', 'processing',
		        'pre-migration-worker', now() + interval '1 minute')`,
		tenantA, []byte(`{"sealed":"ambiguous"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, target.body); err == nil || !strings.Contains(err.Error(), "zero runnable pending or processing secret.sync outbox rows") {
		t.Fatalf("0153 processing-row migration error=%v, want explicit fail-closed refusal", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM information_schema.columns
		     WHERE table_name = 'secret_sync_jobs' AND column_name = 'target_order'
		)`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("failed 0153 migration committed a partial target_order schema")
	}
}

func seedMigration0153SecretSyncPair(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	id, target, jobStatus, outboxStatus string, attempts int,
) int64 {
	t.Helper()
	var outboxID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO outbox
		       (tenant_id, destination, effect_lane, payload, idempotency_key,
		        status, attempts, delivered_at)
		VALUES ($1, 'secret.sync.' || $2, 'secret.sync:' || $2, $3, $4, $5, $6,
		        CASE WHEN $5 = 'delivered' THEN now() ELSE NULL END)
		RETURNING id`, tenantA, target,
		migration0153SecretSyncPayload(id, target, "TOKEN", "binding:"+id),
		"migration-0153:"+id, outboxStatus, attempts).Scan(&outboxID); err != nil {
		t.Fatalf("seed 0153 outbox %s: %v", id, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO secret_sync_jobs
		       (tenant_id, id, secret_name, secret_version, target, remote_key,
		        value_digest, status, outbox_id, attempts, idempotency_key,
		        request_binding, requested_at, updated_at, delivered_at, last_error)
		VALUES ($1, $2, 'migration/secret', 1, $3, 'TOKEN', $4, $5, $6, $7,
		        $8, $9, now(), now(), CASE WHEN $5 = 'delivered' THEN now() ELSE NULL END,
		        CASE WHEN $5 = 'failed' THEN 'legacy receiver failure' ELSE '' END)`,
		tenantA, id, target, strings.Repeat("d", 64), jobStatus, outboxID, attempts,
		"migration-0153:"+id, "binding:"+id); err != nil {
		t.Fatalf("seed 0153 job %s: %v", id, err)
	}
	return outboxID
}

func TestMigration0153RefusesUnsafeInheritedSecretSyncState(t *testing.T) {
	cases := []struct {
		name    string
		want    string
		prepare func(*testing.T, context.Context, *pgxpool.Pool)
	}{
		{
			name: "multiple runnable commands",
			want: "zero runnable pending or processing secret.sync outbox rows",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				seedMigration0153SecretSyncPair(t, ctx, pool, "multiple-first", "ci", "pending", "pending", 0)
				seedMigration0153SecretSyncPair(t, ctx, pool, "multiple-second", "ci", "pending", "pending", 0)
			},
		},
		{
			name: "runnable command already overtaken",
			want: "zero runnable pending or processing secret.sync outbox rows",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				seedMigration0153SecretSyncPair(t, ctx, pool, "inversion-older", "ci", "pending", "pending", 0)
				seedMigration0153SecretSyncPair(t, ctx, pool, "inversion-newer", "ci", "delivered", "delivered", 1)
			},
		},
		{
			name: "higher-id runnable may precede lower-id delivery",
			want: "zero runnable pending or processing secret.sync outbox rows",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				seedMigration0153SecretSyncPair(t, ctx, pool, "ambiguous-lower", "ci", "delivered", "delivered", 1)
				seedMigration0153SecretSyncPair(t, ctx, pool, "ambiguous-higher", "ci", "pending", "pending", 0)
			},
		},
		{
			name: "active compatibility row has no job",
			want: "zero runnable pending or processing secret.sync outbox rows",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				if _, err := pool.Exec(ctx, `
					INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
					VALUES ($1, 'secret.sync.ci', $2, 'migration-0153-orphan')`,
					tenantA, []byte(`{"sealed":"orphan"}`)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "terminal compatibility row has no job",
			want: "outbox row without a projected job",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				if _, err := pool.Exec(ctx, `
					INSERT INTO outbox
					       (tenant_id, destination, payload, idempotency_key, status, attempts, delivered_at)
					VALUES ($1, 'secret.sync.ci', $2, 'migration-0153-terminal-orphan',
					        'delivered', 1, now())`,
					tenantA, []byte(`{"sealed":"orphan"}`)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "pending job has terminal outbox",
			want: "zero pending secret-sync commands",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				seedMigration0153SecretSyncPair(t, ctx, pool, "mismatch", "ci", "pending", "delivered", 1)
			},
		},
		{
			name: "terminal job lost retained outbox",
			want: "job/outbox state mismatch",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				outboxID := seedMigration0153SecretSyncPair(t, ctx, pool, "missing-outbox", "ci", "delivered", "delivered", 1)
				if _, err := pool.Exec(ctx, `DELETE FROM outbox WHERE id = $1`, outboxID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "outbox receiver key differs from job",
			want: "malformed or job-mismatched outbox command",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				outboxID := seedMigration0153SecretSyncPair(t, ctx, pool, "key-drift", "ci", "failed", "failed", 1)
				if _, err := pool.Exec(ctx,
					`UPDATE outbox SET idempotency_key = 'migration-0153:different' WHERE id = $1`, outboxID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "payload binding differs from job",
			want: "malformed or job-mismatched outbox command",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				outboxID := seedMigration0153SecretSyncPair(t, ctx, pool, "payload-drift", "ci", "failed", "failed", 1)
				if _, err := pool.Exec(ctx, `UPDATE outbox SET payload = $2 WHERE id = $1`, outboxID,
					migration0153SecretSyncPayload("wrong-id", "ci", "TOKEN", "binding:payload-drift")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "payload is malformed",
			want: "malformed or job-mismatched outbox command",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				outboxID := seedMigration0153SecretSyncPair(t, ctx, pool, "malformed", "ci", "failed", "failed", 1)
				if _, err := pool.Exec(ctx, `UPDATE outbox SET payload = $2 WHERE id = $1`, outboxID, []byte("not-json")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "duplicate receiver idempotency key",
			want: "duplicate secret-sync outbox receiver key",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				for _, target := range []string{"ci", "vault"} {
					id := "duplicate-" + target
					outboxID := seedMigration0153SecretSyncPair(
						t, ctx, pool, id, target, "delivered", "delivered", 1)
					if _, err := pool.Exec(ctx, `
						UPDATE outbox
						   SET idempotency_key = 'migration-0153:duplicate'
						 WHERE id = $1`, outboxID); err != nil {
						t.Fatal(err)
					}
					if _, err := pool.Exec(ctx, `
						UPDATE secret_sync_jobs
						   SET idempotency_key = 'migration-0153:duplicate'
						 WHERE tenant_id = $1 AND id = $2`, tenantA, id); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			prefix, target := splitMigrationsAtVersion(t, 153)
			dsn := createFreshMigrationDatabase(t)
			pool, err := pgxpool.New(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			applyMigrationFiles(t, ctx, pool, prefix)
			tc.prepare(t, ctx, pool)
			if _, err := pool.Exec(ctx, target.body); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("0153 error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestMigration0153AcceptsTerminalRowsAndBlocksAmbiguousPredecessor(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 153)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	singleStartOutbox := seedMigration0153SecretSyncPair(t, ctx, pool,
		"single-start-delivered", "ci", "delivered", "delivered", 1)
	multiStartOutbox := seedMigration0153SecretSyncPair(t, ctx, pool,
		"multi-start-delivered", "vault", "delivered", "delivered", 2)
	failedOutbox := seedMigration0153SecretSyncPair(t, ctx, pool,
		"offline-disabled-handler-complete", "airgap", "failed", "delivered", 1)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	for _, check := range []struct {
		name       string
		outboxID   int64
		wantStarts int64
	}{
		{name: "single-start delivered", outboxID: singleStartOutbox, wantStarts: 1},
		{name: "multi-start delivered", outboxID: multiStartOutbox, wantStarts: 2},
		{name: "failed", outboxID: failedOutbox, wantStarts: 1},
	} {
		var state, detail string
		var starts int64
		var failureAttempts int
		if err := pool.QueryRow(ctx, `
			SELECT secret_sync_receiver_effect_state, secret_sync_receiver_io_starts,
			       secret_sync_failure_detail, secret_sync_failure_attempts
			  FROM outbox WHERE id = $1`, check.outboxID).Scan(
			&state, &starts, &detail, &failureAttempts); err != nil {
			t.Fatalf("read %s receiver authority: %v", check.name, err)
		}
		if state != "effect_possible" || starts != check.wantStarts || detail != "" || failureAttempts != 0 {
			t.Fatalf("%s receiver authority=(%q,%d,%q,%d), want conservative effect_possible/%d",
				check.name, state, starts, detail, failureAttempts, check.wantStarts)
		}
	}

	type successor struct {
		id        string
		target    string
		order     int64
		wantClaim int64
	}
	for _, candidate := range []successor{
		{id: "after-single-start", target: "ci", order: 200, wantClaim: 1},
		{id: "after-multi-start", target: "vault", order: 201, wantClaim: 0},
		{id: "after-failed", target: "airgap", order: 202, wantClaim: 0},
	} {
		var outboxID int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO outbox
			       (tenant_id, destination, effect_lane, payload, idempotency_key,
			        secret_sync_target_order, secret_sync_order_from_event)
			VALUES ($1, 'secret.sync.' || $2, 'secret.sync:' || $2, $3, $4, $5, true)
			RETURNING id`, tenantA, candidate.target,
			migration0153SecretSyncPayload(candidate.id, candidate.target, "TOKEN", "binding:"+candidate.id),
			"migration-0153:"+candidate.id, candidate.order).Scan(&outboxID); err != nil {
			t.Fatalf("insert %s outbox: %v", candidate.id, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_sync_jobs
			       (tenant_id, tenant_epoch, id, secret_name, secret_version, target, remote_key,
			        value_digest, status, outbox_id, target_order, idempotency_key,
			        request_binding, requested_at, updated_at)
			VALUES ($1, (SELECT epoch_id::text FROM application_secret_tenant_epochs WHERE tenant_id = $1),
			        $2, 'migration/secret', 2, $3, 'TOKEN', $4, 'pending', $5, $6, $7,
			        $8, now(), now())`, tenantA, candidate.id, candidate.target,
			strings.Repeat("e", 64), outboxID, candidate.order,
			"migration-0153:"+candidate.id, "binding:"+candidate.id); err != nil {
			t.Fatalf("insert %s job: %v", candidate.id, err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE projection_checkpoint SET applied_seq = GREATEST(applied_seq, $1), updated_at = now() WHERE id = 1`,
			candidate.order); err != nil {
			t.Fatal(err)
		}
		tag, err := pool.Exec(ctx, `
			UPDATE outbox
			   SET status = 'processing', worker_id = 'migration-claim',
			       lease_until = now() + interval '1 minute'
			 WHERE id = $1 AND status = 'pending'`, outboxID)
		if err != nil {
			t.Fatalf("claim %s: %v", candidate.id, err)
		}
		if tag.RowsAffected() != candidate.wantClaim {
			t.Fatalf("claim %s rows=%d, want %d", candidate.id, tag.RowsAffected(), candidate.wantClaim)
		}
	}
}

func TestMigration0153AcceptsAndRetiresTerminalCleanupCrashRowsAUD109(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 153)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	// Both rows have immutable terminal domain evidence, but the old process died
	// before its generic outbox finalizer changed pending to delivered. They share
	// one target so cleanup of either row also proves that zero-I/O retirement does
	// not wait behind the other row's intentionally conservative FIFO ambiguity.
	first := seedMigration0153SecretSyncPair(t, ctx, pool,
		"terminal-cleanup-first", "airgap", "failed", "pending", 1)
	second := seedMigration0153SecretSyncPair(t, ctx, pool,
		"terminal-cleanup-second", "airgap", "failed", "pending", 1)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	for _, outboxID := range []int64{first, second} {
		tag, err := pool.Exec(ctx, `
			UPDATE outbox
			   SET status = 'processing', attempts = attempts + 1,
			       worker_id = 'migration-cleanup', lease_until = now() + interval '1 minute'
			 WHERE id = $1 AND status = 'pending'`, outboxID)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("claim terminal cleanup %d = (%d, %v), want one zero-I/O claim",
				outboxID, tag.RowsAffected(), err)
		}
		tag, err = pool.Exec(ctx, `
			UPDATE outbox
			   SET status = 'delivered', delivered_at = now(),
			       worker_id = NULL, lease_until = NULL
			 WHERE id = $1 AND status = 'processing' AND worker_id = 'migration-cleanup'`, outboxID)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("retire terminal cleanup %d = (%d, %v), want one zero-I/O finalization",
				outboxID, tag.RowsAffected(), err)
		}
		var status, effectState, failureDetail string
		var starts int64
		var failureAttempts int
		if err := pool.QueryRow(ctx, `
			SELECT status, secret_sync_receiver_effect_state,
			       secret_sync_receiver_io_starts, secret_sync_failure_detail,
			       secret_sync_failure_attempts
			  FROM outbox WHERE id = $1`, outboxID).Scan(
			&status, &effectState, &starts, &failureDetail, &failureAttempts); err != nil {
			t.Fatal(err)
		}
		if status != "delivered" || effectState != "effect_possible" ||
			starts != 1 || failureDetail != "" || failureAttempts != 0 {
			t.Fatalf("terminal cleanup %d authority=(%q,%q,%d,%q,%d), want retired but ambiguous legacy evidence",
				outboxID, status, effectState, starts, failureDetail, failureAttempts)
		}
	}
}

func testMigration0137RelayExternalPollers(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 137)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	for index, tenantID := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, $2)`, tenantID, fmt.Sprintf("relay-migration-%d", index)); err != nil {
			t.Fatalf("seed tenant %s: %v", tenantID, err)
		}
	}
	const agentID = "99999999-9999-9999-9999-999999999999"
	if _, err := pool.Exec(ctx, `
		INSERT INTO outbox
		       (tenant_id, destination, payload, idempotency_key, status,
		        claimed_by_agent_id, claim_expires_at, claim_completed_at)
		VALUES ($1, 'cmdb.sync', '{}'::bytea, 'pre-0137-split', 'pending',
		        $2::uuid, '2026-08-10T04:00:00Z'::timestamptz, '2026-08-10T03:00:00Z'::timestamptz)`,
		tenantA, agentID); err != nil {
		t.Fatalf("seed split outbox row: %v", err)
	}
	for _, row := range []struct {
		tenantID, tokenRef string
	}{
		{tenantA, "env:LEGACY_TOKEN"},
		{tenantB, "secret://estate/token"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO cmdb_reconcile_schedules
			       (tenant_id, instance_url, token_ref, interval_seconds, enabled, execution)
			VALUES ($1, 'https://now.example', $2, 3600, true, 'control_plane')`, row.tenantID, row.tokenRef); err != nil {
			t.Fatalf("seed CMDB schedule %s: %v", row.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO mdm_poll_schedules
			       (tenant_id, mdm, base_url, token_ref, interval_seconds, enabled, execution)
			VALUES ($1, 'intune', 'https://graph.example', $2, 3600, true, 'control_plane')`, row.tenantID, row.tokenRef); err != nil {
			t.Fatalf("seed MDM schedule %s: %v", row.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO ticket_intake_schedules
			       (tenant_id, system, instance_url, token_ref, sn_table,
			        subject_field, profile_field, interval_seconds, enabled)
			VALUES ($1, 'servicenow', 'https://now.example', $2, 'incident',
			        'u_subject', 'u_profile', 3600, true)`, row.tenantID, row.tokenRef); err != nil {
			t.Fatalf("seed ticket schedule %s: %v", row.tenantID, err)
		}
	}

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	var status string
	var deliveredAt, completedAt string
	if err := pool.QueryRow(ctx, `
		SELECT status, delivered_at::text, claim_completed_at::text
		  FROM outbox WHERE tenant_id = $1 AND idempotency_key = 'pre-0137-split'`, tenantA).
		Scan(&status, &deliveredAt, &completedAt); err != nil {
		t.Fatalf("inspect repaired outbox row: %v", err)
	}
	if status != "delivered" || deliveredAt == "" || deliveredAt != completedAt {
		t.Fatalf("split row repair status=%q delivered=%q completed=%q", status, deliveredAt, completedAt)
	}

	for _, table := range []string{"cmdb_reconcile_schedules", "mdm_poll_schedules"} {
		for _, row := range []struct {
			tenantID    string
			wantEnabled bool
		}{
			{tenantA, false},
			{tenantB, true},
		} {
			var execution, lastError string
			var enabled bool
			query := fmt.Sprintf(`SELECT execution, enabled, last_error FROM %s WHERE tenant_id = $1`, table) // #nosec G201 -- closed test table list above
			if err := pool.QueryRow(ctx, query, row.tenantID).Scan(&execution, &enabled, &lastError); err != nil {
				t.Fatalf("inspect %s/%s: %v", table, row.tenantID, err)
			}
			if execution != "relay" || enabled != row.wantEnabled || (!row.wantEnabled && !strings.Contains(lastError, "secret://")) {
				t.Fatalf("%s/%s execution=%q enabled=%t error=%q", table, row.tenantID, execution, enabled, lastError)
			}
		}
	}
	for _, row := range []struct {
		tenantID    string
		wantEnabled bool
	}{
		{tenantA, false},
		{tenantB, true},
	} {
		var enabled bool
		var lastError string
		if err := pool.QueryRow(ctx, `SELECT enabled, last_error FROM ticket_intake_schedules WHERE tenant_id = $1`, row.tenantID).
			Scan(&enabled, &lastError); err != nil {
			t.Fatalf("inspect ticket schedule %s: %v", row.tenantID, err)
		}
		if enabled != row.wantEnabled || (!row.wantEnabled && !strings.Contains(lastError, "secret://")) {
			t.Fatalf("ticket/%s enabled=%t error=%q", row.tenantID, enabled, lastError)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE mdm_poll_schedules SET execution = 'control_plane' WHERE tenant_id = $1`, tenantB); err == nil {
		t.Fatal("0137 relay-only MDM constraint accepted control_plane")
	}
	var sourceEventColumn bool
	if err := pool.QueryRow(ctx, `
		SELECT count(*) = 1 FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = 'owner_ownership_conflicts' AND column_name = 'source_event_id'`).
		Scan(&sourceEventColumn); err != nil || !sourceEventColumn {
		t.Fatalf("source_event_id column present=%t err=%v", sourceEventColumn, err)
	}
}

func testMigration0136FleetReissuanceCursorDefaults(t *testing.T) {
	stable := `
		SELECT id::text, tenant_id::text, issuer_id::text, status, phase, reason,
		       batch_size::text, connector, target, graph_impact::text,
		       affected_identity_ids::text, replacement_identity_ids::text,
		       revoked_identity_ids::text, connector_delivery_ids::text,
		       batches::text, health_gates::text, failed_targets::text,
		       rollback_refs::text, evidence_bundle_format, evidence_bundle,
		       idempotency_key, created_by, created_at::text, updated_at::text
		  FROM incident_fleet_reissuance_runs
		 ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 136, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenantID := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, `
					INSERT INTO incident_fleet_reissuance_runs
					       (id, tenant_id, issuer_id, status, phase, reason,
					        batch_size, connector, target, graph_impact,
					        affected_identity_ids, batches, health_gates,
					        rollback_refs, idempotency_key, created_by,
					        created_at, updated_at)
					VALUES ($1, $2, $3, 'running', 'canary_waiting_verification',
					        'pre-0136 compromised issuer', 1, 'nginx', 'edge/prod',
					        '{"affected":1}'::jsonb, ARRAY[$4],
					        '[{"index":1,"status":"planned"}]'::jsonb,
					        '[{"name":"replacement deployment","status":"not_evaluated"}]'::jsonb,
					        ARRAY['restore:edge'], $5, 'migration-harness',
					        '2026-08-09T10:00:00Z'::timestamptz,
					        '2026-08-09T10:01:00Z'::timestamptz)`,
					uuid(tenantID, 13600+index), tenantID, uuid(tenantID, 13610+index),
					uuid(tenantID, 13620+index), fmt.Sprintf("pre-0136-%d", index)); err != nil {
					t.Fatalf("seed pre-0136 fleet run %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var cursorOK, haltOK, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(next_batch_index = 1),
				       bool_and(halted_reason = ''),
				       bool_and(next_batch_index IS NOT NULL AND halted_reason IS NOT NULL)
				  FROM incident_fleet_reissuance_runs`).Scan(&rows, &cursorOK, &haltOK, &nonnull); err != nil {
				t.Fatalf("inspect 0136 fleet cursor defaults: %v", err)
			}
			if rows != want || !cursorOK || !haltOK || !nonnull {
				t.Fatalf("0136 defaults rows=%d want=%d cursor=%t halt=%t nonnull=%t",
					rows, want, cursorOK, haltOK, nonnull)
			}
		})
}

func testMigration0094CryptoAssetProjectionOrderDefaults(t *testing.T) {
	stable := `
		SELECT id::text, tenant_id::text, signature, kind, location, algorithm,
		       key_bits::text, protocol, cipher, library, strength,
		       quantum_vulnerable::text, out_of_policy::text, reasons::text, created_at::text
		  FROM crypto_assets
		 ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 94, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenantID := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, `
					INSERT INTO crypto_assets
					       (id, tenant_id, signature, kind, location, protocol, strength,
					        quantum_vulnerable, out_of_policy, reasons, created_at)
					VALUES ($1, $2, $3, 'host-config', $4, 'TLSv1.0', 'weak', true, true,
					        ARRAY['legacy protocol'], '2026-07-31T00:00:00Z'::timestamptz)`,
					uuid(tenantID, 9400+index), tenantID, "host-config|edge-"+tenantID+"|TLSv1.0",
					"edge-"+tenantID); err != nil {
					t.Fatalf("seed pre-0094 crypto asset %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, beforeCount int) {
			var rows int
			var zeroSequence, active bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(event_sequence = 0), bool_and(is_active)
				  FROM crypto_assets`).Scan(&rows, &zeroSequence, &active); err != nil {
				t.Fatalf("inspect 0094 crypto-asset defaults: %v", err)
			}
			if rows != beforeCount || !zeroSequence || !active {
				t.Fatalf("0094 defaults mismatch: rows=%d want=%d zero_sequence=%t active=%t",
					rows, beforeCount, zeroSequence, active)
			}
		})
}

func testMigration0072ConnectorTargetRevisionBackfill(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 72)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	for index, tenantID := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO deployment_targets (id, tenant_id, name, type, config, created_at)
			VALUES ($1, $2, $3, 'kubernetes', $4::jsonb, $5::timestamptz)`,
			uuid(tenantID, 7200+index), tenantID, "edge-"+tenantID,
			fmt.Sprintf(`{"namespace":"tenant-%d"}`, index),
			fmt.Sprintf("2026-02-0%dT03:04:05Z", index+1)); err != nil {
			t.Fatalf("seed pre-0072 deployment target %s: %v", tenantID, err)
		}
	}
	stable := `
		SELECT id::text, tenant_id::text, name, type, config::text, created_at::text
		  FROM deployment_targets
		 ORDER BY tenant_id, id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0072 changed existing target content: count %d/%d checksum %s/%s",
			beforeCount, afterCount, beforeChecksum, afterChecksum)
	}

	var revisions int
	var targetIDs, names, types, configs, enabled, created bool
	if err := pool.QueryRow(ctx, `
		SELECT count(*),
		       bool_and(r.revision_id = 'legacy:' || t.id::text),
		       bool_and(r.name = t.name),
		       bool_and(r.type = t.type),
		       bool_and(r.config = t.config),
		       bool_and(r.enabled AND t.enabled),
		       bool_and(r.created_at = t.created_at)
		  FROM deployment_targets t
		  JOIN deployment_target_revisions r
		    ON r.tenant_id = t.tenant_id AND r.target_id = t.id AND r.revision_id = t.revision_id`).
		Scan(&revisions, &targetIDs, &names, &types, &configs, &enabled, &created); err != nil {
		t.Fatalf("inspect 0072 revision backfill: %v", err)
	}
	if revisions != beforeCount || !targetIDs || !names || !types || !configs || !enabled || !created {
		t.Fatalf("0072 revision backfill mismatch: rows=%d want=%d id=%t name=%t type=%t config=%t enabled=%t created=%t",
			revisions, beforeCount, targetIDs, names, types, configs, enabled, created)
	}
}

func testMigration0075DynamicSecretPreparationDefault(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 75)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	for index, tenantID := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO dynamic_secret_leases
			       (tenant_id, id, idempotency_key, provider, role, backend_ref,
			        sealed_credential, state, issue_outbox_id, issued_at, expires_at,
			        hard_expires_at, updated_at)
			VALUES ($1, $2, $3, 'postgresql', 'reader', '', ''::bytea, 'pending', $4,
			        '2026-03-01T00:00:00Z'::timestamptz,
			        '2026-03-01T00:10:00Z'::timestamptz,
			        '2026-03-01T00:20:00Z'::timestamptz,
			        '2026-03-01T00:00:00Z'::timestamptz)`,
			tenantID, fmt.Sprintf("lease-%d", index), fmt.Sprintf("lease-idem-%d", index), 7500+index); err != nil {
			t.Fatalf("seed pre-0075 dynamic lease %s: %v", tenantID, err)
		}
	}
	stable := `
		SELECT tenant_id::text, id, idempotency_key, provider, role, backend_ref,
		       encode(sealed_credential, 'hex'), state, issue_outbox_id::text,
		       issued_at::text, expires_at::text, hard_expires_at::text, updated_at::text
		  FROM dynamic_secret_leases
		 ORDER BY tenant_id, id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0075 changed existing lease content: count %d/%d checksum %s/%s",
			beforeCount, afterCount, beforeChecksum, afterChecksum)
	}
	var rows int
	var empty, nonnull bool
	if err := pool.QueryRow(ctx, `
		SELECT count(*), bool_and(octet_length(sealed_preparation) = 0),
		       bool_and(sealed_preparation IS NOT NULL)
		  FROM dynamic_secret_leases`).Scan(&rows, &empty, &nonnull); err != nil {
		t.Fatalf("inspect 0075 sealed preparation backfill: %v", err)
	}
	if rows != beforeCount || !empty || !nonnull {
		t.Fatalf("0075 preparation default mismatch: rows=%d want=%d empty=%t nonnull=%t",
			rows, beforeCount, empty, nonnull)
	}
}

// runPopulatedDefaultMigrationHarness applies exactly migrations 1..N-1,
// inserts real multi-tenant rows in the historical shape, fingerprints every
// pre-existing column named by stableProjection, applies only N, and proves N
// neither drops nor rewrites that content before checking its filled defaults.
func runPopulatedDefaultMigrationHarness(
	t *testing.T,
	version int,
	stableProjection string,
	seed func(context.Context, *pgxpool.Pool),
	assertDefaults func(context.Context, *pgxpool.Pool, int),
) {
	t.Helper()
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, version)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database for %04d: %v", version, err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	seed(ctx, pool)
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stableProjection)
	if beforeCount < 2 {
		t.Fatalf("%04d precondition: populated N-1 table has %d rows, want multi-tenant rows", version, beforeCount)
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stableProjection)
	if afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("%04d changed N-1 content: count %d/%d checksum %s/%s",
			version, beforeCount, afterCount, beforeChecksum, afterChecksum)
	}
	assertDefaults(ctx, pool, beforeCount)
}

func testMigration0077IdempotencyRequestBindingDefault(t *testing.T) {
	stable := `
		SELECT tenant_id::text, key, status, encode(COALESCE(result, ''::bytea), 'hex'),
		       created_at::text, COALESCE(completed_at::text, '')
		  FROM idempotency_keys
		 ORDER BY tenant_id, key`
	runPopulatedDefaultMigrationHarness(t, 77, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenantID := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, `
					INSERT INTO idempotency_keys
					       (tenant_id, key, status, result, created_at, completed_at)
					VALUES ($1, $2, 'completed', $3,
					        '2026-07-01T10:00:00Z'::timestamptz,
					        '2026-07-01T10:00:01Z'::timestamptz)`,
					tenantID, fmt.Sprintf("pre-0077-key-%d", index), []byte(fmt.Sprintf("result-%d", index))); err != nil {
					t.Fatalf("seed pre-0077 idempotency row %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var empty, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(request_binding = ''),
				       bool_and(request_binding IS NOT NULL)
				  FROM idempotency_keys`).Scan(&rows, &empty, &nonnull); err != nil {
				t.Fatalf("inspect 0077 request_binding default: %v", err)
			}
			if rows != want || !empty || !nonnull {
				t.Fatalf("0077 defaults rows=%d want=%d empty=%t nonnull=%t", rows, want, empty, nonnull)
			}
		})
}

func testMigration0078DynamicSecretRequestBindingDefault(t *testing.T) {
	stable := `
		SELECT tenant_id::text, id, idempotency_key, provider, role, backend_ref,
		       encode(sealed_preparation, 'hex'), encode(sealed_credential, 'hex'),
		       state, issue_outbox_id::text, revocation_status,
		       COALESCE(revoke_outbox_id::text, ''), last_error, issued_at::text,
		       expires_at::text, hard_expires_at::text, COALESCE(revoked_at::text, ''),
		       updated_at::text
		  FROM dynamic_secret_leases
		 ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 78, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenantID := range []string{tenantA, tenantB} {
				state, backendRef, credential := "pending", "", []byte{}
				if index == 1 {
					state, backendRef, credential = "active", "provider-handle-1", []byte("sealed-credential-1")
				}
				if _, err := pool.Exec(ctx, `
					INSERT INTO dynamic_secret_leases
					       (tenant_id, id, idempotency_key, provider, role, backend_ref,
					        sealed_preparation, sealed_credential, state, issue_outbox_id,
					        issued_at, expires_at, hard_expires_at, updated_at)
					VALUES ($1, $2, $3, 'postgresql', 'reader', $4, $5, $6, $7, $8,
					        '2026-07-02T10:00:00Z'::timestamptz,
					        '2026-07-02T10:30:00Z'::timestamptz,
					        '2026-07-02T11:00:00Z'::timestamptz,
					        '2026-07-02T10:00:02Z'::timestamptz)`,
					tenantID, fmt.Sprintf("pre-0078-lease-%d", index), fmt.Sprintf("pre-0078-key-%d", index),
					backendRef, []byte(fmt.Sprintf("sealed-preparation-%d", index)), credential, state, 7800+index); err != nil {
					t.Fatalf("seed pre-0078 dynamic lease %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var empty, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(request_binding = ''),
				       bool_and(request_binding IS NOT NULL)
				  FROM dynamic_secret_leases`).Scan(&rows, &empty, &nonnull); err != nil {
				t.Fatalf("inspect 0078 request_binding default: %v", err)
			}
			if rows != want || !empty || !nonnull {
				t.Fatalf("0078 defaults rows=%d want=%d empty=%t nonnull=%t", rows, want, empty, nonnull)
			}
		})
}

func testMigration0079ManagedKeyRequestBindingDefault(t *testing.T) {
	stable := `
		SELECT tenant_id::text, operation_id, provider, action, key_id, algorithm,
		       status, result_key_id, encode(public_der, 'hex'), result_state,
		       outbox_id::text, last_error, created_at::text, updated_at::text
		  FROM managed_key_operations
		 ORDER BY tenant_id, operation_id`
	runPopulatedDefaultMigrationHarness(t, 79, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenantID := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx,
					`INSERT INTO tenants (tenant_id, name) VALUES ($1, $2) ON CONFLICT (tenant_id) DO NOTHING`,
					tenantID, fmt.Sprintf("pre-0079-tenant-%d", index)); err != nil {
					t.Fatalf("seed pre-0079 tenant %s: %v", tenantID, err)
				}
				status, resultKeyID, resultState, publicDER := "queued", "", "", []byte{}
				if index == 1 {
					status, resultKeyID, resultState, publicDER = "completed", "key-v1", "active", []byte("public-der-1")
				}
				if _, err := pool.Exec(ctx, `
					INSERT INTO managed_key_operations
					       (tenant_id, operation_id, provider, action, key_id, algorithm,
					        status, result_key_id, public_der, result_state, outbox_id,
					        last_error, created_at, updated_at)
					VALUES ($1, $2, 'aws-kms', 'generate', '', 'ecdsa-p256',
					        $3, $4, $5, $6, $7, '',
					        '2026-07-03T10:00:00Z'::timestamptz,
					        '2026-07-03T10:00:01Z'::timestamptz)`,
					tenantID, fmt.Sprintf("pre-0079-operation-%d", index), status,
					resultKeyID, publicDER, resultState, 7900+index); err != nil {
					t.Fatalf("seed pre-0079 managed-key operation %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var empty, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(request_binding = ''),
				       bool_and(request_binding IS NOT NULL)
				  FROM managed_key_operations`).Scan(&rows, &empty, &nonnull); err != nil {
				t.Fatalf("inspect 0079 request_binding default: %v", err)
			}
			if rows != want || !empty || !nonnull {
				t.Fatalf("0079 defaults rows=%d want=%d empty=%t nonnull=%t", rows, want, empty, nonnull)
			}
		})
}

func testMigration0080ExternalCARequestBindingDefaults(t *testing.T) {
	stable := `
		SELECT id::text, tenant_id::text, COALESCE(owner_id::text, ''), subject,
		       array_to_string(sans, ','), issuer, serial, fingerprint, key_algorithm,
		       COALESCE(not_before::text, ''), COALESCE(not_after::text, ''),
		       deployment_location, source, created_at::text, status,
		       COALESCE(replaces_id::text, ''), COALESCE(revoked_at::text, ''),
		       revocation_reason, COALESCE(renewed_at::text, ''),
		       COALESCE(alerted_at::text, ''), issuance_idempotency_key,
		       encode(certificate_der, 'hex')
		  FROM certificates
		 ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 80, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenantID := range []string{tenantA, tenantB} {
				if _, err := pool.Exec(ctx, `
					INSERT INTO certificates
					       (id, tenant_id, subject, sans, issuer, serial, fingerprint,
					        key_algorithm, not_before, not_after, deployment_location,
					        source, created_at, status, revocation_reason,
					        issuance_idempotency_key, certificate_der)
					VALUES ($1, $2, $3, ARRAY[$4, $5]::text[], 'issuer-1', $6, $7,
					        'ecdsa-p256', '2026-07-04T10:00:00Z'::timestamptz,
					        '2026-08-04T10:00:00Z'::timestamptz, $8, 'external-ca',
					        '2026-07-04T10:00:01Z'::timestamptz, 'active', '', $9, $10)`,
					uuid(tenantID, 8000+index), tenantID, fmt.Sprintf("CN=pre-0080-%d", index),
					fmt.Sprintf("pre-0080-%d.example", index), fmt.Sprintf("alt-pre-0080-%d.example", index),
					fmt.Sprintf("serial-%d", index), fmt.Sprintf("fingerprint-%d", index),
					fmt.Sprintf("cluster-%d", index), fmt.Sprintf("issuance-key-%d", index),
					[]byte(fmt.Sprintf("certificate-der-%d", index))); err != nil {
					t.Fatalf("seed pre-0080 certificate %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var bindingsEmpty, pemEmpty, responseEmpty, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(issuance_request_binding = ''),
				       bool_and(octet_length(certificate_pem) = 0),
				       bool_and(octet_length(issuance_response) = 0),
				       bool_and(issuance_request_binding IS NOT NULL AND certificate_pem IS NOT NULL AND issuance_response IS NOT NULL)
				  FROM certificates`).Scan(&rows, &bindingsEmpty, &pemEmpty, &responseEmpty, &nonnull); err != nil {
				t.Fatalf("inspect 0080 request binding/PEM defaults: %v", err)
			}
			if rows != want || !bindingsEmpty || !pemEmpty || !responseEmpty || !nonnull {
				t.Fatalf("0080 defaults rows=%d want=%d binding_empty=%t pem_empty=%t response_empty=%t nonnull=%t",
					rows, want, bindingsEmpty, pemEmpty, responseEmpty, nonnull)
			}
		})
}

func testMigration0081DynamicSecretCommandBackfill(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 81)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	for index, tenantID := range []string{tenantA, tenantB} {
		binding := "sha256:authenticated-issue-command"
		state, backendRef, sealed := "active", "backend-ref", []byte("sealed-result")
		if index == 1 {
			binding, state, backendRef, sealed = "", "pending", "", []byte{}
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO dynamic_secret_leases
			       (tenant_id, id, idempotency_key, request_binding, provider, role,
			        backend_ref, sealed_preparation, sealed_credential, state,
			        issue_outbox_id, issued_at, expires_at, hard_expires_at, updated_at)
			VALUES ($1, $2, $3, $4, 'postgresql', 'reader', $5, ''::bytea, $6,
			        $7, $8, '2026-07-11T18:00:00Z', '2026-07-11T18:30:00Z',
			        '2026-07-11T19:00:00Z', '2026-07-11T18:00:00Z')`,
			tenantID, fmt.Sprintf("lease-%d", index), fmt.Sprintf("issue-key-%d", index), binding,
			backendRef, sealed, state, 8100+index); err != nil {
			t.Fatalf("seed pre-0081 dynamic lease %s: %v", tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_sync_jobs
			       (tenant_id, id, secret_name, secret_version, target, remote_key,
			        value_digest, status, outbox_id, idempotency_key, requested_at, updated_at)
			VALUES ($1, $2, 'production/deploy', 1, 'github-actions', 'DEPLOY_TOKEN',
			        $3, 'pending', $4, $5, '2026-07-11T18:00:00Z', '2026-07-11T18:00:00Z')`,
			tenantID, fmt.Sprintf("sync-%d", index), strings.Repeat(fmt.Sprintf("%d", index+1), 64),
			8200+index, fmt.Sprintf("secret.sync.github-actions:sync-key-%d", index)); err != nil {
			t.Fatalf("seed pre-0081 sync job %s: %v", tenantID, err)
		}
	}
	stable := `
		SELECT tenant_id::text, id, idempotency_key, request_binding, provider, role,
		       backend_ref, state, issue_outbox_id::text, issued_at::text,
		       expires_at::text, hard_expires_at::text, updated_at::text
		  FROM dynamic_secret_leases
		 ORDER BY tenant_id, id`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0081 changed lease content: count %d/%d checksum %s/%s",
			beforeCount, afterCount, beforeChecksum, afterChecksum)
	}

	var operations, exactBinding, legacyBinding, statuses int
	if err := pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE idempotency_key = 'issue-key-0' AND request_binding = 'sha256:authenticated-issue-command'),
		       count(*) FILTER (WHERE idempotency_key = 'issue-key-1' AND request_binding = 'legacy-unbound'),
		       count(*) FILTER (WHERE (idempotency_key = 'issue-key-0' AND status = 'completed')
		                            OR (idempotency_key = 'issue-key-1' AND status = 'pending'))
		  FROM dynamic_secret_operations`).Scan(&operations, &exactBinding, &legacyBinding, &statuses); err != nil {
		t.Fatalf("inspect 0081 operation backfill: %v", err)
	}
	if operations != 2 || exactBinding != 1 || legacyBinding != 1 || statuses != 2 {
		t.Fatalf("0081 operation backfill rows=%d exact=%d legacy=%d statuses=%d", operations, exactBinding, legacyBinding, statuses)
	}
	var syncRows int
	var emptyBindings bool
	if err := pool.QueryRow(ctx,
		`SELECT count(*), bool_and(request_binding = '') FROM secret_sync_jobs`).Scan(&syncRows, &emptyBindings); err != nil {
		t.Fatalf("inspect 0081 secret-sync binding default: %v", err)
	}
	if syncRows != 2 || !emptyBindings {
		t.Fatalf("0081 secret-sync default rows=%d empty_bindings=%t", syncRows, emptyBindings)
	}
}

func testMigration0082ConnectorRightSizeOperationDefaults(t *testing.T) {
	assertMigrationUsesConcurrentIndex(t, 82, "CREATE UNIQUE INDEX CONCURRENTLY")
	stable := `
		SELECT id::text, tenant_id::text, playbook_id, target_identity_id,
		       inventory_id, status, phase, action, reason, connector, target,
		       COALESCE(outbox_id::text, ''), COALESCE(connector_delivery_id::text, ''),
		       scope_delta::text, array_to_string(evidence_refs, ','),
		       array_to_string(rollback_refs, ','), idempotency_key, created_by,
		       created_at::text, updated_at::text
		  FROM remediation_playbook_runs
		 ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 82, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for tenantIndex, tenantID := range []string{tenantA, tenantB} {
				for duplicate := 0; duplicate < 2; duplicate++ {
					row := tenantIndex*2 + duplicate
					if _, err := pool.Exec(ctx, `
						INSERT INTO remediation_playbook_runs
						       (id, tenant_id, playbook_id, target_identity_id, inventory_id,
						        status, phase, action, reason, connector, target, outbox_id,
						        connector_delivery_id, scope_delta, evidence_refs, rollback_refs,
						        idempotency_key, created_by, created_at, updated_at)
						VALUES ($1, $2, 'nhi-right-size', $3, $4, 'queued',
						        'right_size_connector_intent_queued', 'right_size', $5,
						        'least-privilege', $6, $7, $8, $9::jsonb,
						        ARRAY[$10, $11]::text[], ARRAY[$12]::text[], $13, $14,
						        '2026-07-06T10:00:00Z'::timestamptz,
						        '2026-07-06T10:00:01Z'::timestamptz)`,
						uuid(tenantID, 8200+row), tenantID, fmt.Sprintf("identity-%d", row),
						fmt.Sprintf("identity/identity-%d", row), fmt.Sprintf("right-size reason %d", row),
						fmt.Sprintf("service-%d", row), 8200+row, uuid(tenantID, 8250+row),
						fmt.Sprintf(`{"remove_scopes":["write:%d"],"risk_score":%d}`, row, 80+row),
						"nhi_posture:CAP-POST-01", fmt.Sprintf("connector_delivery:%d", row),
						fmt.Sprintf("restore-grants-%d", row), "legacy-shared-key-"+tenantID,
						fmt.Sprintf("operator-%d", row)); err != nil {
						t.Fatalf("seed pre-0082 remediation row %s/%d: %v", tenantID, duplicate, err)
					}
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var bindingEmpty, statusZero, responseEmpty, terminalEmpty, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(request_binding = ''),
				       bool_and(initial_http_status = 0),
				       bool_and(octet_length(initial_response) = 0),
				       bool_and(terminal_reason = ''),
				       bool_and(request_binding IS NOT NULL
				                AND initial_http_status IS NOT NULL
				                AND initial_response IS NOT NULL
				                AND terminal_reason IS NOT NULL)
				  FROM remediation_playbook_runs`).Scan(
				&rows, &bindingEmpty, &statusZero, &responseEmpty, &terminalEmpty, &nonnull); err != nil {
				t.Fatalf("inspect 0082 durable-operation defaults: %v", err)
			}
			if rows != want || !bindingEmpty || !statusZero || !responseEmpty || !terminalEmpty || !nonnull {
				t.Fatalf("0082 defaults rows=%d want=%d binding=%t status=%t response=%t terminal=%t nonnull=%t",
					rows, want, bindingEmpty, statusZero, responseEmpty, terminalEmpty, nonnull)
			}
			assertIndexReady(t, ctx, pool, "remediation_playbook_runs_right_size_idempotency_idx")
		})
}

func testMigration0083OutboxEffectLaneDefault(t *testing.T) {
	assertMigrationUsesConcurrentIndex(t, 83, "CREATE INDEX CONCURRENTLY")
	stable := `
		SELECT id::text, tenant_id::text, destination, encode(payload, 'hex'),
		       idempotency_key, status, attempts::text, COALESCE(last_error, ''),
		       next_attempt_at::text, created_at::text,
		       COALESCE(delivered_at::text, ''), COALESCE(worker_id, ''),
		       COALESCE(lease_until::text, '')
		  FROM outbox
		 ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 83, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for tenantIndex, tenantID := range []string{tenantA, tenantB} {
				for rowIndex, status := range []string{"processing", "pending"} {
					row := tenantIndex*2 + rowIndex
					var workerID any
					var leaseUntil any
					if status == "processing" {
						workerID = fmt.Sprintf("worker-%d", row)
						leaseUntil = "2026-07-07T10:05:00Z"
					}
					if _, err := pool.Exec(ctx, `
						INSERT INTO outbox
						       (tenant_id, destination, payload, idempotency_key, status,
						        attempts, last_error, next_attempt_at, created_at,
						        worker_id, lease_until)
						VALUES ($1, $2, $3, $4, $5, $6, $7,
						        '2026-07-07T10:00:00Z'::timestamptz,
						        '2026-07-07T09:59:00Z'::timestamptz, $8, $9::timestamptz)`,
						tenantID, fmt.Sprintf("connector.receiver-%d", rowIndex),
						[]byte(fmt.Sprintf("payload-%d", row)), fmt.Sprintf("pre-0083-key-%d", row),
						status, row+1, fmt.Sprintf("attempt-%d", row), workerID, leaseUntil); err != nil {
						t.Fatalf("seed pre-0083 outbox row %s/%s: %v", tenantID, status, err)
					}
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var empty, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(effect_lane = ''),
				       bool_and(effect_lane IS NOT NULL)
				  FROM outbox`).Scan(&rows, &empty, &nonnull); err != nil {
				t.Fatalf("inspect 0083 effect_lane default: %v", err)
			}
			if rows != want || !empty || !nonnull {
				t.Fatalf("0083 defaults rows=%d want=%d empty=%t nonnull=%t", rows, want, empty, nonnull)
			}
			assertIndexReady(t, ctx, pool, "outbox_effect_lane_processing_idx")
		})
}

func assertMigrationUsesConcurrentIndex(t *testing.T, version int, indexDDL string) {
	t.Helper()
	_, target := splitMigrationsAtVersion(t, version)
	if !target.noTx {
		t.Fatalf("%s must declare migrate: no-transaction", target.name)
	}
	if !strings.Contains(strings.ToUpper(target.body), strings.ToUpper(indexDDL)) {
		t.Fatalf("%s missing online DDL %q", target.name, indexDDL)
	}
}

func assertIndexReady(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) {
	t.Helper()
	var valid, ready bool
	if err := pool.QueryRow(ctx, `
		SELECT i.indisvalid, i.indisready
		  FROM pg_index i
		  JOIN pg_class c ON c.oid = i.indexrelid
		 WHERE c.relname = $1`, name).Scan(&valid, &ready); err != nil {
		t.Fatalf("inspect index %s: %v", name, err)
	}
	if !valid || !ready {
		t.Fatalf("index %s valid=%t ready=%t, want true/true", name, valid, ready)
	}
}

func testMigration0089GCPWorkloadIdentityDefault(t *testing.T) {
	stable := `
		SELECT tenant_id::text, id::text, name, provider, role_arn, audience,
		       subject, target_id, array_to_string(allowed_remote_key_prefixes, ','),
		       workload_proof_ref, trust_source_id::text, enabled::text, status,
		       status_reason, created_at::text, updated_at::text
		  FROM secret_sync_workload_identity_sources
		 ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 89, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenantID := range []string{tenantA, tenantB} {
				trustID := uuid(tenantID, 8900+index)
				sourceID := uuid(tenantID, 8910+index)
				if _, err := pool.Exec(ctx, `
					INSERT INTO tenants (tenant_id, name)
					VALUES ($1, $2)
					ON CONFLICT (tenant_id) DO NOTHING`, tenantID, fmt.Sprintf("pre-0089-tenant-%d", index)); err != nil {
					t.Fatalf("seed pre-0089 tenant %s: %v", tenantID, err)
				}
				if _, err := pool.Exec(ctx, `
					INSERT INTO workload_attester_trust_sources
					       (id, tenant_id, name, method, issuer, audience, jwks,
					        enabled, created_at, updated_at)
					VALUES ($1, $2, $3, 'k8s_sat', 'https://issuer.example.test',
					        'trstctl', '{"keys":[]}'::jsonb, true,
					        '2026-07-28T10:00:00Z'::timestamptz,
					        '2026-07-28T10:00:01Z'::timestamptz)`,
					trustID, tenantID, fmt.Sprintf("pre-0089-trust-%d", index)); err != nil {
					t.Fatalf("seed pre-0089 trust source %s: %v", tenantID, err)
				}
				if _, err := pool.Exec(ctx, `
					INSERT INTO secret_sync_workload_identity_sources
					       (tenant_id, id, name, provider, role_arn, audience, subject,
					        target_id, allowed_remote_key_prefixes, workload_proof_ref,
					        trust_source_id, enabled, status, status_reason, created_at, updated_at)
					VALUES ($1, $2, $3, 'aws', $4, 'trstctl', $5, $6, ARRAY['prod/'],
					        $7, $8, true, 'ready', 'configured',
					        '2026-07-28T10:01:00Z'::timestamptz,
					        '2026-07-28T10:01:01Z'::timestamptz)`,
					tenantID, sourceID, fmt.Sprintf("pre-0089-source-%d", index),
					fmt.Sprintf("arn:aws:iam::12345678901%d:role/sync", index),
					fmt.Sprintf("system:serviceaccount:sync:worker-%d", index),
					fmt.Sprintf("aws-target-%d", index), fmt.Sprintf("secret://sync/proof-%d", index),
					trustID); err != nil {
					t.Fatalf("seed pre-0089 workload identity source %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var empty, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*), bool_and(service_account = ''),
				       bool_and(service_account IS NOT NULL)
				  FROM secret_sync_workload_identity_sources`).Scan(&rows, &empty, &nonnull); err != nil {
				t.Fatalf("inspect 0089 service-account default: %v", err)
			}
			if rows != want || !empty || !nonnull {
				t.Fatalf("0089 defaults rows=%d want=%d empty=%t nonnull=%t",
					rows, want, empty, nonnull)
			}
		})
}

func testMigration0090AzureWorkloadIdentityDefaults(t *testing.T) {
	stable := `
		SELECT tenant_id::text, id::text, name, provider, role_arn, service_account,
		       audience, subject, target_id, array_to_string(allowed_remote_key_prefixes, ','),
		       workload_proof_ref, trust_source_id::text, enabled::text, status,
		       status_reason, created_at::text, updated_at::text
		  FROM secret_sync_workload_identity_sources
		 ORDER BY tenant_id, id`
	runPopulatedDefaultMigrationHarness(t, 90, stable,
		func(ctx context.Context, pool *pgxpool.Pool) {
			for index, tenantID := range []string{tenantA, tenantB} {
				trustID := uuid(tenantID, 9000+index)
				sourceID := uuid(tenantID, 9010+index)
				if _, err := pool.Exec(ctx, `
					INSERT INTO tenants (tenant_id, name)
					VALUES ($1, $2)
					ON CONFLICT (tenant_id) DO NOTHING`, tenantID, fmt.Sprintf("pre-0090-tenant-%d", index)); err != nil {
					t.Fatalf("seed pre-0090 tenant %s: %v", tenantID, err)
				}
				if _, err := pool.Exec(ctx, `
					INSERT INTO workload_attester_trust_sources
					       (id, tenant_id, name, method, issuer, audience, jwks,
					        enabled, created_at, updated_at)
					VALUES ($1, $2, $3, 'k8s_sat', 'https://issuer.example.test',
					        'trstctl', '{"keys":[]}'::jsonb, true,
					        '2026-07-28T11:00:00Z'::timestamptz,
					        '2026-07-28T11:00:01Z'::timestamptz)`,
					trustID, tenantID, fmt.Sprintf("pre-0090-trust-%d", index)); err != nil {
					t.Fatalf("seed pre-0090 trust source %s: %v", tenantID, err)
				}
				provider := "aws"
				roleARN := fmt.Sprintf("arn:aws:iam::12345678901%d:role/sync", index)
				serviceAccount := ""
				if index == 1 {
					provider = "gcp"
					roleARN = ""
					serviceAccount = "sync@example.iam.gserviceaccount.com"
				}
				if _, err := pool.Exec(ctx, `
					INSERT INTO secret_sync_workload_identity_sources
					       (tenant_id, id, name, provider, role_arn, service_account,
					        audience, subject, target_id, allowed_remote_key_prefixes,
					        workload_proof_ref, trust_source_id, enabled, status,
					        status_reason, created_at, updated_at)
					VALUES ($1, $2, $3, $4, $5, $6, 'trstctl', $7, $8, ARRAY['prod/'],
					        $9, $10, true, 'ready', 'configured',
					        '2026-07-28T11:01:00Z'::timestamptz,
					        '2026-07-28T11:01:01Z'::timestamptz)`,
					tenantID, sourceID, fmt.Sprintf("pre-0090-source-%d", index),
					provider, roleARN, serviceAccount,
					fmt.Sprintf("system:serviceaccount:sync:worker-%d", index),
					fmt.Sprintf("%s-target-%d", provider, index),
					fmt.Sprintf("secret://sync/proof-%d", index), trustID); err != nil {
					t.Fatalf("seed pre-0090 workload identity source %s: %v", tenantID, err)
				}
			}
		},
		func(ctx context.Context, pool *pgxpool.Pool, want int) {
			var rows int
			var empty, nonnull bool
			if err := pool.QueryRow(ctx, `
				SELECT count(*),
				       bool_and(azure_tenant_id = '' AND client_id = '' AND target_scope = ''),
				       bool_and(azure_tenant_id IS NOT NULL AND client_id IS NOT NULL AND target_scope IS NOT NULL)
				  FROM secret_sync_workload_identity_sources`).Scan(&rows, &empty, &nonnull); err != nil {
				t.Fatalf("inspect 0090 Azure field defaults: %v", err)
			}
			if rows != want || !empty || !nonnull {
				t.Fatalf("0090 defaults rows=%d want=%d empty=%t nonnull=%t",
					rows, want, empty, nonnull)
			}
		})
}

func testMigration0092IdempotencyResultCodecClassification(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 92)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	type historicalRow struct {
		tenantID        string
		key             string
		binding         string
		result          []byte
		operationTenant string
		operationKey    string
		operationBind   string
		wantCodec       string
	}
	v1 := func(payload string) []byte {
		return append([]byte{'C', 'S', 'L', '1', 1}, []byte(payload)...)
	}
	rows := []historicalRow{
		{tenantA, "exact-a", "sha256:exact-a", v1("a"), tenantA, "exact-a", "sha256:exact-a", "sealed-dynamic-lease-v1"},
		{tenantB, "exact-b", "sha256:exact-b", v1("b"), tenantB, "exact-b", "sha256:exact-b", "sealed-dynamic-lease-v1"},
		{tenantA, "wrong-tenant", "sha256:wrong-tenant", v1("tenant"), tenantB, "wrong-tenant", "sha256:wrong-tenant", "raw-v0"},
		{tenantA, "wrong-key", "sha256:wrong-key", v1("key"), tenantA, "different-operation-key", "sha256:wrong-key", "raw-v0"},
		{tenantB, "wrong-binding", "sha256:idempotency-binding", v1("binding"), tenantB, "wrong-binding", "sha256:operation-binding", "raw-v0"},
		{tenantB, "wrong-header", "sha256:wrong-header", append([]byte{'C', 'S', 'L', '1', 2}, []byte("future")...), tenantB, "wrong-header", "sha256:wrong-header", "raw-v0"},
	}
	for index, row := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO idempotency_keys
			       (tenant_id, key, status, result, request_binding, created_at, completed_at)
			VALUES ($1, $2, 'completed', $3, $4,
			        '2026-07-30T10:00:00Z'::timestamptz,
			        '2026-07-30T10:00:01Z'::timestamptz)`,
			row.tenantID, row.key, row.result, row.binding); err != nil {
			t.Fatalf("seed pre-0092 idempotency row %d: %v", index, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO dynamic_secret_operations
			       (tenant_id, operation_id, idempotency_key, request_binding, action,
			        lease_id, response, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 'issue', $5, '{}'::jsonb, 'completed',
			        '2026-07-30T10:00:00Z'::timestamptz,
			        '2026-07-30T10:00:01Z'::timestamptz)`,
			row.operationTenant, fmt.Sprintf("issue:codec-%d", index), row.operationKey,
			row.operationBind, fmt.Sprintf("lease-codec-%d", index)); err != nil {
			t.Fatalf("seed pre-0092 dynamic operation %d: %v", index, err)
		}
	}

	stable := `
		SELECT tenant_id::text, key, status, encode(result, 'hex'), request_binding,
		       created_at::text, completed_at::text
		  FROM idempotency_keys
		 ORDER BY tenant_id, key`
	beforeCount, beforeChecksum := checksumQuery(t, ctx, pool, stable)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	afterCount, afterChecksum := checksumQuery(t, ctx, pool, stable)
	if afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("0092 changed historical idempotency bytes: count %d/%d checksum %s/%s",
			beforeCount, afterCount, beforeChecksum, afterChecksum)
	}

	for _, row := range rows {
		var codec string
		if err := pool.QueryRow(ctx, `
			SELECT result_codec
			  FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2`,
			row.tenantID, row.key).Scan(&codec); err != nil {
			t.Fatalf("read classified codec for %s/%s: %v", row.tenantID, row.key, err)
		}
		if codec != row.wantCodec {
			t.Errorf("%s/%s result_codec=%q, want %q", row.tenantID, row.key, codec, row.wantCodec)
		}
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO idempotency_keys (tenant_id, key, status, result, request_binding)
		VALUES ($1, 'post-0092-default', 'completed', 'new-result'::bytea, '')`,
		tenantA); err != nil {
		t.Fatalf("insert post-0092 default row: %v", err)
	}
	var codec string
	if err := pool.QueryRow(ctx, `
		SELECT result_codec
		  FROM idempotency_keys
		 WHERE tenant_id = $1 AND key = 'post-0092-default'`,
		tenantA).Scan(&codec); err != nil {
		t.Fatalf("read post-0092 default: %v", err)
	}
	if codec != "raw-v0" {
		t.Fatalf("post-0092 default codec=%q, want raw-v0", codec)
	}
}

// TestMigration0071HistoricalLifecycleCompositePKContent is the SCHEMA-007
// historical-shape harness. Current greenfield replay reaches v70 with composite
// primary keys because the base migration has since been corrected, but installed
// databases from the old lineage reached v70 with owners/issuers/identities using
// PRIMARY KEY (id) plus UNIQUE (tenant_id, id). This test reconstructs that exact
// shape, seeds multi-tenant lifecycle rows and dependent FK rows, applies only
// 0071, then proves row content, FK validity, RLS scoping, and composite PK
// semantics.
func TestMigration0071HistoricalLifecycleCompositePKContent(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 71)

	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh content database: %v", err)
	}
	t.Cleanup(pool.Close)

	applyMigrationFiles(t, ctx, pool, prefix)
	forceMigration0071HistoricalLifecycleShape(t, ctx, pool)
	for _, table := range []string{"owners", "issuers", "identities"} {
		assertPrimaryKeyColumns(t, ctx, pool, table, []string{"id"})
	}

	seedMigration0071LifecycleContent(t, ctx, pool)
	before := captureMigration0071LifecycleContent(t, ctx, pool)
	for table, snap := range before {
		if snap.count == 0 {
			t.Fatalf("precondition: %s should have historical rows before migration 0071", table)
		}
	}
	assertMigration0071ForeignKeysValid(t, ctx, pool)
	assertMigration0071OnlineSafetyClassification(t, target)

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})

	after := captureMigration0071LifecycleContent(t, ctx, pool)
	for table, b := range before {
		a, ok := after[table]
		if !ok {
			t.Errorf("%s vanished after migration 0071", table)
			continue
		}
		if a.count != b.count {
			t.Errorf("%s row count changed across 0071: before=%d after=%d", table, b.count, a.count)
		}
		if a.checksum != b.checksum {
			t.Errorf("%s content changed across 0071: before=%s after=%s", table, b.checksum, a.checksum)
		}
	}
	for _, table := range []string{"owners", "issuers", "identities"} {
		assertPrimaryKeyColumns(t, ctx, pool, table, []string{"tenant_id", "id"})
	}
	assertMigration0071ForeignKeysValid(t, ctx, pool)
	assertMigration0071TenantScopedReads(t, ctx, pool, 1)
	assertMigration0071AllowsCrossTenantLifecycleIDs(t, ctx, pool)
}

// TestFutureValueChangingMigrationsRequireContentHarness is the SCHEMA-002 tripwire
// for future migrations. Creating a new table with defaults is just schema shape;
// backfilling from existing rows or default-filling columns on an already-existing
// table changes live values and needs a migration-content subtest like the two
// above.
func TestFutureValueChangingMigrationsRequireContentHarness(t *testing.T) {
	valueChanging := regexp.MustCompile(`(?is)\binsert\s+into\b.+\bselect\b|\balter\s+table\b.+\badd\s+column\b.+\bdefault\b`)
	for _, m := range orderedMigrationFiles(t) {
		if m.version <= 51 {
			continue
		}
		if valueChangingMigrationContentHarnesses[m.version] {
			continue
		}
		if valueChanging.MatchString(stripSQLLineComments(m.body)) {
			t.Errorf("%s looks like it writes live values; add an exact N-1 -> N case to TestMigrationDataContentBackfills or classify why it is shape-only", m.name)
		}
	}
}

// migrationFile is one ordered migration on disk.
type migrationFile struct {
	name    string
	version int
	body    string
	noTx    bool
}

func orderedMigrationFiles(t *testing.T) []migrationFile {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var out []migrationFile
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("migrations", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		body := string(raw)
		out = append(out, migrationFile{
			name:    e.Name(),
			version: migrationNumber(e.Name()),
			body:    body,
			noTx:    isNoTransactionMigration(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out
}

func splitMigrationsAtVersion(t *testing.T, version int) ([]migrationFile, migrationFile) {
	t.Helper()
	var prefix []migrationFile
	var target migrationFile
	found := false
	for _, m := range orderedMigrationFiles(t) {
		if m.version < version {
			prefix = append(prefix, m)
			continue
		}
		if m.version == version {
			target = m
			found = true
		}
	}
	if !found {
		t.Fatalf("migration %04d not found", version)
	}
	if len(prefix) == 0 {
		t.Fatalf("migration %04d has empty prefix; expected an N-1 boundary", version)
	}
	return prefix, target
}

func isNoTransactionMigration(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "--") {
			continue
		}
		c := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "--")))
		if c == "migrate: no-transaction" || c == "migrate: no-tx" {
			return true
		}
	}
	return false
}

// applyMigrationFiles applies migrations the way Migrate does: a no-transaction
// migration's statements run individually outside a transaction (so CREATE INDEX
// CONCURRENTLY is legal); a normal migration's whole body runs in one statement.
func applyMigrationFiles(t *testing.T, ctx context.Context, pool *pgxpool.Pool, files []migrationFile) {
	t.Helper()
	for _, m := range files {
		if m.noTx {
			for _, stmt := range splitStatements(m.body) {
				sql := strings.TrimSpace(stmt.sql)
				if stripSQLLineComments(sql) == "" || strings.TrimSpace(stripSQLLineComments(sql)) == "" {
					continue
				}
				if _, err := pool.Exec(ctx, sql); err != nil {
					t.Fatalf("apply no-tx migration %s stmt: %v\n%s", m.name, err, sql)
				}
			}
			continue
		}
		if _, err := pool.Exec(ctx, m.body); err != nil {
			t.Fatalf("apply migration %s: %v", m.name, err)
		}
	}
}

// seededContentSnapshot is one table's count and deterministic content checksum.
type seededContentSnapshot struct {
	count    int
	checksum string
}

func captureSeededContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string]seededContentSnapshot {
	t.Helper()
	out := make(map[string]seededContentSnapshot, len(seededContentColumns))
	for table, proj := range seededContentColumns {
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		// md5 of the row-ordered concatenation of the stable columns. chr(31) (the
		// ASCII unit separator) joins columns and chr(30) joins rows, so neither can
		// collide with ordinary data. A NULL aggregate (no rows) is coalesced to a
		// constant so the checksum is always defined.
		q := fmt.Sprintf(
			`SELECT COALESCE(md5(string_agg(row_blob, chr(30) ORDER BY %s)), 'empty')
			   FROM (SELECT concat_ws(chr(31), %s) AS row_blob, %s FROM %s) s`,
			proj.orderBy, proj.cols, proj.orderBy, table)
		var sum string
		if err := pool.QueryRow(ctx, q).Scan(&sum); err != nil {
			t.Fatalf("checksum %s: %v", table, err)
		}
		out[table] = seededContentSnapshot{count: count, checksum: sum}
	}
	return out
}

func assertColumnDefault(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, column, _ string) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		                 WHERE table_name = $1 AND column_name = $2)`,
		table, column).Scan(&exists); err != nil {
		t.Fatalf("column existence %s.%s: %v", table, column, err)
	}
	if !exists {
		t.Errorf("expected additive column %s.%s to exist after migration", table, column)
	}
}

func checksumQuery(t *testing.T, ctx context.Context, pool *pgxpool.Pool, selectSQL string) (int, string) {
	t.Helper()
	q := fmt.Sprintf(`
		SELECT count(*), COALESCE(md5(string_agg(row_blob, chr(30))), 'empty')
		  FROM (SELECT concat_ws(chr(31), q.*) AS row_blob FROM (%s) q) s`, selectSQL)
	var count int
	var checksum string
	if err := pool.QueryRow(ctx, q).Scan(&count, &checksum); err != nil {
		t.Fatalf("checksum query: %v\n%s", err, q)
	}
	return count, checksum
}

func seedSecretStoreBackfillContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID string
		name     string
		sealed   []byte
		version  int
		updated  string
	}{
		{tenantID: tenantA, name: "api-key", sealed: []byte("sealed-secret-a"), version: 3, updated: "2026-01-02T03:04:05Z"},
		{tenantID: tenantA, name: "webhook-token", sealed: []byte("sealed-hook-a"), version: 8, updated: "2026-01-03T03:04:05Z"},
		{tenantID: tenantB, name: "api-key", sealed: []byte("sealed-secret-b"), version: 5, updated: "2026-01-04T03:04:05Z"},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_store (tenant_id, name, sealed, version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5::timestamptz, $5::timestamptz)`,
			r.tenantID, r.name, r.sealed, r.version, r.updated); err != nil {
			t.Fatalf("seed secret_store %s/%s: %v", r.tenantID, r.name, err)
		}
	}
}

func seedDiscoveryFindingBackfillContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID    string
		sourceID    string
		runID       string
		findingID   string
		kind        string
		ref         string
		provenance  string
		fingerprint string
		riskScore   int
		metadata    string
	}{
		{
			tenantID:    tenantA,
			sourceID:    uuid(tenantA, 51),
			runID:       uuid(tenantA, 52),
			findingID:   uuid(tenantA, 53),
			kind:        "x509",
			ref:         "spiffe://tenant-a/workload-a",
			provenance:  "scan:a",
			fingerprint: "sha256:a",
			riskScore:   17,
			metadata:    `{"issuer":"ca-a","path":"/etc/a.pem"}`,
		},
		{
			tenantID:    tenantB,
			sourceID:    uuid(tenantB, 51),
			runID:       uuid(tenantB, 52),
			findingID:   uuid(tenantB, 53),
			kind:        "ssh",
			ref:         "host-b",
			provenance:  "scan:b",
			fingerprint: "sha256:b",
			riskScore:   29,
			metadata:    `{"host":"b.example.test","port":22}`,
		},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO discovery_sources (id, tenant_id, kind, name, config, created_at, updated_at)
			VALUES ($1, $2, 'network', $3, '{"cidr":"10.0.0.0/24"}'::jsonb, '2026-01-05T03:04:05Z'::timestamptz, '2026-01-05T03:04:05Z'::timestamptz)`,
			r.sourceID, r.tenantID, "source-"+r.tenantID); err != nil {
			t.Fatalf("seed discovery source %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO discovery_runs (id, tenant_id, source_id, status, dry_run, requested_by, targets, discovered, failed, rejected, error, started_at, completed_at, created_at)
			VALUES ($1, $2, $3, 'completed', false, 'schema-test', 2, 1, 0, 0, '', '2026-01-05T03:04:06Z'::timestamptz, '2026-01-05T03:04:07Z'::timestamptz, '2026-01-05T03:04:05Z'::timestamptz)`,
			r.runID, r.tenantID, r.sourceID); err != nil {
			t.Fatalf("seed discovery run %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO discovery_findings (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, risk_score, metadata, discovered_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, '2026-01-05T03:04:08Z'::timestamptz)`,
			r.findingID, r.tenantID, r.runID, r.sourceID, r.kind, r.ref, r.provenance, r.fingerprint, r.riskScore, r.metadata); err != nil {
			t.Fatalf("seed discovery finding %s: %v", r.tenantID, err)
		}
	}
}

func discoveryFindingStableProjectionSQL() string {
	return `
		SELECT id::text,
		       tenant_id::text,
		       run_id::text,
		       source_id::text,
		       kind,
		       ref,
		       provenance,
		       fingerprint,
		       risk_score::text,
		       metadata::text,
		       discovered_at::text
		  FROM discovery_findings
		 ORDER BY tenant_id, id`
}

func seedNotificationRoutingPolicyMetadataContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID           string
		id                 string
		name               string
		channelsBySeverity string
		defaultChannels    string
		createdAt          string
		updatedAt          string
	}{
		{
			tenantID:           tenantA,
			id:                 uuid(tenantA, 62),
			name:               "critical-escalation",
			channelsBySeverity: `{"critical":["slack","webhook"],"warning":["email"]}`,
			defaultChannels:    `["email"]`,
			createdAt:          "2026-01-06T03:04:05Z",
			updatedAt:          "2026-01-06T03:04:06Z",
		},
		{
			tenantID:           tenantB,
			id:                 uuid(tenantB, 62),
			name:               "low-signal-digest",
			channelsBySeverity: `{"low":["email"]}`,
			defaultChannels:    `["webhook"]`,
			createdAt:          "2026-01-07T03:04:05Z",
			updatedAt:          "2026-01-07T03:04:06Z",
		},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO notification_routing_policies (
			    id, tenant_id, name, channels_by_severity, default_channels, created_at, updated_at
			)
			VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::timestamptz, $7::timestamptz)`,
			r.id, r.tenantID, r.name, r.channelsBySeverity, r.defaultChannels, r.createdAt, r.updatedAt); err != nil {
			t.Fatalf("seed notification routing policy %s/%s: %v", r.tenantID, r.name, err)
		}
	}
}

func notificationRoutingPolicyStableProjectionSQL() string {
	return `
		SELECT id::text,
		       tenant_id::text,
		       name,
		       channels_by_severity::text,
		       default_channels::text,
		       created_at::text,
		       updated_at::text
		  FROM notification_routing_policies
		 ORDER BY tenant_id, id`
}

func forceMigration0071HistoricalLifecycleShape(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	stmts := []string{
		`ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_tenant_id_owner_id_fkey`,
		`ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_tenant_id_issuer_id_fkey`,
		`ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_tenant_id_owner_id_fkey`,
		`ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_tenant_id_identity_id_fkey`,

		`ALTER TABLE owners DROP CONSTRAINT IF EXISTS owners_tenant_id_id_key`,
		`ALTER TABLE owners DROP CONSTRAINT IF EXISTS owners_pkey`,
		`ALTER TABLE owners ADD CONSTRAINT owners_pkey PRIMARY KEY (id)`,
		`ALTER TABLE owners ADD CONSTRAINT owners_tenant_id_id_key UNIQUE (tenant_id, id)`,

		`ALTER TABLE issuers DROP CONSTRAINT IF EXISTS issuers_tenant_id_id_key`,
		`ALTER TABLE issuers DROP CONSTRAINT IF EXISTS issuers_pkey`,
		`ALTER TABLE issuers ADD CONSTRAINT issuers_pkey PRIMARY KEY (id)`,
		`ALTER TABLE issuers ADD CONSTRAINT issuers_tenant_id_id_key UNIQUE (tenant_id, id)`,

		`ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_tenant_id_id_key`,
		`ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_pkey`,
		`ALTER TABLE identities ADD CONSTRAINT identities_pkey PRIMARY KEY (id)`,
		`ALTER TABLE identities ADD CONSTRAINT identities_tenant_id_id_key UNIQUE (tenant_id, id)`,

		`ALTER TABLE identities ADD CONSTRAINT identities_tenant_id_owner_id_fkey FOREIGN KEY (tenant_id, owner_id) REFERENCES owners (tenant_id, id)`,
		`ALTER TABLE identities ADD CONSTRAINT identities_tenant_id_issuer_id_fkey FOREIGN KEY (tenant_id, issuer_id) REFERENCES issuers (tenant_id, id)`,
		`ALTER TABLE certificates ADD CONSTRAINT certificates_tenant_id_owner_id_fkey FOREIGN KEY (tenant_id, owner_id) REFERENCES owners (tenant_id, id)`,
		`ALTER TABLE attestations ADD CONSTRAINT attestations_tenant_id_identity_id_fkey FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)`,
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("force historical 0071 shape: %v\n%s", err, stmt)
		}
	}
}

func seedMigration0071LifecycleContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID   string
		ownerID    string
		issuerID   string
		identityID string
		certID     string
		attestID   string
		label      string
	}{
		{
			tenantID:   tenantA,
			ownerID:    uuid(tenantA, 7101),
			issuerID:   uuid(tenantA, 7102),
			identityID: uuid(tenantA, 7103),
			certID:     uuid(tenantA, 7104),
			attestID:   uuid(tenantA, 7105),
			label:      "alpha",
		},
		{
			tenantID:   tenantB,
			ownerID:    uuid(tenantB, 7201),
			issuerID:   uuid(tenantB, 7202),
			identityID: uuid(tenantB, 7203),
			certID:     uuid(tenantB, 7204),
			attestID:   uuid(tenantB, 7205),
			label:      "bravo",
		},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO owners (id, tenant_id, kind, name, email, created_at)
			VALUES ($1, $2, 'Service', $3, $4, '2026-02-01T00:00:00Z'::timestamptz)`,
			r.ownerID, r.tenantID, "owner-"+r.label, r.label+"@example.test"); err != nil {
			t.Fatalf("seed 0071 owner %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO issuers (id, tenant_id, kind, name, chain, public_key, internal, created_at)
			VALUES ($1, $2, 'x509', $3, ARRAY[$4]::text[], $5, true, '2026-02-01T00:01:00Z'::timestamptz)`,
			r.issuerID, r.tenantID, "issuer-"+r.label, "chain-"+r.label, "pub-"+r.label); err != nil {
			t.Fatalf("seed 0071 issuer %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO identities (
			    id, tenant_id, kind, name, owner_id, issuer_id, status,
			    not_before, not_after, attributes, created_at
			)
			VALUES (
			    $1, $2, 'x509', $3, $4, $5, 'issued',
			    '2026-02-01T00:02:00Z'::timestamptz,
			    '2026-05-01T00:02:00Z'::timestamptz,
			    $6::jsonb,
			    '2026-02-01T00:02:30Z'::timestamptz
			)`,
			r.identityID, r.tenantID, "identity-"+r.label, r.ownerID, r.issuerID, `{"env":"`+r.label+`"}`); err != nil {
			t.Fatalf("seed 0071 identity %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO certificates (
			    id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
			    key_algorithm, not_before, not_after, deployment_location, source, created_at
			)
			VALUES (
			    $1, $2, $3, $4, ARRAY[$5]::text[], $6, $7, $8,
			    'ecdsa-p256',
			    '2026-02-01T00:03:00Z'::timestamptz,
			    '2026-05-01T00:03:00Z'::timestamptz,
			    $9, 'schema-007',
			    '2026-02-01T00:03:30Z'::timestamptz
			)`,
			r.certID, r.tenantID, r.ownerID, "CN="+r.label+".example.test", r.label+".example.test",
			"issuer-"+r.label, "serial-"+r.label, "fp-"+r.label, "/etc/trstctl/"+r.label); err != nil {
			t.Fatalf("seed 0071 certificate %s: %v", r.tenantID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO attestations (id, tenant_id, identity_id, kind, evidence, verified_at, created_at)
			VALUES (
			    $1, $2, $3, 'manual',
			    $4::jsonb,
			    '2026-02-01T00:04:00Z'::timestamptz,
			    '2026-02-01T00:04:30Z'::timestamptz
			)`,
			r.attestID, r.tenantID, r.identityID, `{"ticket":"`+r.label+`"}`); err != nil {
			t.Fatalf("seed 0071 attestation %s: %v", r.tenantID, err)
		}
	}
}

var migration0071LifecycleContentColumns = map[string]struct {
	cols    string
	orderBy string
}{
	"owners": {
		cols:    "id::text, tenant_id::text, kind, name, email, created_at::text",
		orderBy: "tenant_id, id",
	},
	"issuers": {
		cols:    "id::text, tenant_id::text, kind, name, array_to_string(chain, ','), public_key, internal::text, created_at::text",
		orderBy: "tenant_id, id",
	},
	"identities": {
		cols:    "id::text, tenant_id::text, kind, name, owner_id::text, issuer_id::text, status, not_before::text, not_after::text, attributes::text, created_at::text",
		orderBy: "tenant_id, id",
	},
	"certificates": {
		cols:    "id::text, tenant_id::text, owner_id::text, subject, array_to_string(sans, ','), issuer, serial, fingerprint, key_algorithm, not_before::text, not_after::text, deployment_location, source, created_at::text",
		orderBy: "tenant_id, id",
	},
	"attestations": {
		cols:    "id::text, tenant_id::text, identity_id::text, kind, evidence::text, verified_at::text, created_at::text",
		orderBy: "tenant_id, id",
	},
}

func captureMigration0071LifecycleContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string]seededContentSnapshot {
	t.Helper()
	out := make(map[string]seededContentSnapshot, len(migration0071LifecycleContentColumns))
	for table, proj := range migration0071LifecycleContentColumns {
		q := fmt.Sprintf(
			`SELECT count(*), COALESCE(md5(string_agg(row_blob, chr(30) ORDER BY %s)), 'empty')
			   FROM (SELECT concat_ws(chr(31), %s) AS row_blob, %s FROM %s) s`,
			proj.orderBy, proj.cols, proj.orderBy, table)
		var count int
		var sum string
		if err := pool.QueryRow(ctx, q).Scan(&count, &sum); err != nil {
			t.Fatalf("capture 0071 content for %s: %v", table, err)
		}
		out[table] = seededContentSnapshot{count: count, checksum: sum}
	}
	return out
}

func assertPrimaryKeyColumns(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string, want []string) {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT a.attname
		  FROM pg_constraint c
		  JOIN unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
		 WHERE c.conrelid = $1::regclass
		   AND c.contype = 'p'
		 ORDER BY k.ord`, table)
	if err != nil {
		t.Fatalf("query primary key for %s: %v", table, err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("scan primary key for %s: %v", table, err)
		}
		got = append(got, col)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate primary key for %s: %v", table, err)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s primary key columns = %v, want %v", table, got, want)
	}
}

func assertMigration0071ForeignKeysValid(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	checks := []struct {
		table  string
		name   string
		target string
	}{
		{table: "identities", name: "identities_tenant_id_owner_id_fkey", target: "owners"},
		{table: "identities", name: "identities_tenant_id_issuer_id_fkey", target: "issuers"},
		{table: "certificates", name: "certificates_tenant_id_owner_id_fkey", target: "owners"},
		{table: "attestations", name: "attestations_tenant_id_identity_id_fkey", target: "identities"},
	}
	for _, c := range checks {
		var valid bool
		if err := pool.QueryRow(ctx, `
			SELECT convalidated
			  FROM pg_constraint
			 WHERE conrelid = $1::regclass
			   AND conname = $2
			   AND contype = 'f'
			   AND confrelid = $3::regclass`,
			c.table, c.name, c.target).Scan(&valid); err != nil {
			t.Fatalf("query FK %s.%s -> %s: %v", c.table, c.name, c.target, err)
		}
		if !valid {
			t.Fatalf("FK %s.%s -> %s is not validated", c.table, c.name, c.target)
		}
	}
}

func assertMigration0071OnlineSafetyClassification(t *testing.T, target migrationFile) {
	t.Helper()
	if target.version != 71 {
		t.Fatalf("target migration version = %d, want 71", target.version)
	}
	dropPrimaryKeyConstraintRe := regexp.MustCompile(`(?i)\bdrop\s+constraint\s+(?:if\s+exists\s+)?"?[a-z0-9_]*pkey"?\b`)
	addPrimaryKeyConstraintRe := regexp.MustCompile(`(?i)\badd\s+(?:constraint\s+"?[a-z0-9_]+"?\s+)?primary\s+key\b`)
	want := map[string]bool{
		"owners/drop-pkey":     false,
		"owners/add-pkey":      false,
		"issuers/drop-pkey":    false,
		"issuers/add-pkey":     false,
		"identities/drop-pkey": false,
		"identities/add-pkey":  false,
	}
	for _, stmt := range splitStatements(target.body) {
		body := stripSQLLineComments(stmt.sql)
		dropsPK := dropPrimaryKeyConstraintRe.MatchString(body)
		addsPK := addPrimaryKeyConstraintRe.MatchString(body)
		if !dropsPK && !addsPK {
			continue
		}
		table, ok := alterTargetTable(body)
		if !ok {
			t.Fatalf("0071 lock-heavy primary-key statement has no ALTER TABLE target: %s", oneLine(body))
		}
		op := "drop-pkey"
		if addsPK {
			op = "add-pkey"
		}
		key := table + "/" + op
		if _, ok := want[key]; !ok {
			t.Fatalf("0071 has unexpected primary-key rewrite classification %s in %s", key, oneLine(body))
		}
		if !stmt.onlineSafe {
			t.Fatalf("0071 %s lacks an online-safe justification comment: %s", key, oneLine(stmt.sql))
		}
		want[key] = true
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("0071 missing online-safety classification for %s", key)
		}
	}
}

func assertMigration0071TenantScopedReads(t *testing.T, ctx context.Context, pool *pgxpool.Pool, wantPerTenant int) {
	t.Helper()
	for _, tenantID := range []string{tenantA, tenantB} {
		for _, table := range []string{"owners", "issuers", "identities", "certificates", "attestations"} {
			got := countRowsAsTenant(t, ctx, pool, tenantID, table)
			if got != wantPerTenant {
				t.Fatalf("%s visible %s rows = %d, want %d", tenantID, table, got, wantPerTenant)
			}
		}
	}
}

func countRowsAsTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, table string) int {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tenant-scoped count: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE trstctl_app"); err != nil {
		t.Fatalf("set tenant role: %v", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", tenantID); err != nil {
		t.Fatalf("set tenant id: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
		t.Fatalf("tenant-scoped count %s/%s: %v", tenantID, table, err)
	}
	return count
}

func assertMigration0071AllowsCrossTenantLifecycleIDs(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	ownerID := uuid(tenantA, 7101)
	issuerID := uuid(tenantA, 7102)
	identityID := uuid(tenantA, 7103)
	if _, err := pool.Exec(ctx, `
		INSERT INTO owners (id, tenant_id, kind, name, email, created_at)
		VALUES ($1, $2, 'Service', 'tenant-b-duplicate-owner', 'dup@example.test', '2026-02-02T00:00:00Z'::timestamptz)`,
		ownerID, tenantB); err != nil {
		t.Fatalf("insert cross-tenant duplicate owner id after 0071: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO issuers (id, tenant_id, kind, name, chain, public_key, internal, created_at)
		VALUES ($1, $2, 'x509', 'tenant-b-duplicate-issuer', ARRAY['dup-chain']::text[], 'dup-pub', true, '2026-02-02T00:01:00Z'::timestamptz)`,
		issuerID, tenantB); err != nil {
		t.Fatalf("insert cross-tenant duplicate issuer id after 0071: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identities (
		    id, tenant_id, kind, name, owner_id, issuer_id, status,
		    not_before, not_after, attributes, created_at
		)
		VALUES (
		    $1, $2, 'x509', 'tenant-b-duplicate-identity', $3, $4, 'issued',
		    '2026-02-02T00:02:00Z'::timestamptz,
		    '2026-05-02T00:02:00Z'::timestamptz,
		    '{"env":"duplicate"}'::jsonb,
		    '2026-02-02T00:02:30Z'::timestamptz
		)`,
		identityID, tenantB, ownerID, issuerID); err != nil {
		t.Fatalf("insert cross-tenant duplicate identity id after 0071: %v", err)
	}
	if got := countRowsAsTenant(t, ctx, pool, tenantA, "owners"); got != 1 {
		t.Fatalf("tenant A owner visibility after cross-tenant duplicate = %d, want 1", got)
	}
	if got := countRowsAsTenant(t, ctx, pool, tenantB, "owners"); got != 2 {
		t.Fatalf("tenant B owner visibility after cross-tenant duplicate = %d, want 2", got)
	}
}

// seedMigrationContent inserts representative rows for tenantID across the read
// model, independent state, sealed-secret blobs, the outbox, and the idempotency
// ledger. It uses the superuser pool (bypasses RLS) so it can write explicit
// tenant_id values for multiple tenants directly; FORCE RLS is exercised elsewhere.
func seedMigrationContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	ownerID := uuid(tenantID, 21)
	stmts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO owners (id, tenant_id, kind, name, email) VALUES ($1,$2,'Service','svc-owner',$3)`,
			[]any{ownerID, tenantID, "owner-" + tenantID + "@example.test"}},
		{`INSERT INTO certificates (id, tenant_id, owner_id, subject, sans, fingerprint)
		  VALUES ($1,$2,$3,'CN=seed', ARRAY['a.seed.test','b.seed.test']::text[], $4)`,
			[]any{uuid(tenantID, 22), tenantID, ownerID, "fp-" + tenantID}},
		{`INSERT INTO ssh_keys (id, tenant_id, fingerprint, comment, location)
		  VALUES ($1,$2,$3,'ops@host','/etc/ssh')`,
			[]any{uuid(tenantID, 23), tenantID, "ssh-" + tenantID}},
		{`INSERT INTO secret_store (tenant_id, name, sealed) VALUES ($1,'api-key',$2)`,
			[]any{tenantID, []byte("sealed-secret-" + tenantID)}},
		{`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed)
		  VALUES ($1,$2,'issuer','ref-1','api_key',$3)`,
			[]any{uuid(tenantID, 24), tenantID, []byte("sealed-cred-" + tenantID)}},
		{`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status)
		  VALUES ($1,'webhook',$2,$3,'pending')`,
			[]any{tenantID, []byte("payload-" + tenantID), "idem-out-" + tenantID}},
		{`INSERT INTO idempotency_keys (tenant_id, key, status, result)
		  VALUES ($1,$2,'completed',$3)`,
			[]any{tenantID, "idem-" + tenantID, []byte("result-" + tenantID)}},
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed content for %s: %v\n%s", tenantID, err, s.sql)
		}
	}
}

// seedOutboxClaimContent puts a realistic in-flight queue in front of migration
// 0098: entries in different states, for different tenants, with the retry
// metadata a real backlog carries. The migration must leave every byte of it
// alone.
func seedOutboxClaimContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID    string
		destination string
		payload     []byte
		idemKey     string
		status      string
		attempts    int
		lastError   string
		delivered   bool
	}{
		{tenantID: tenantA, destination: "ca.issue", payload: []byte(`{"identity_id":"a1"}`), idemKey: "issue:a1", status: "pending"},
		{tenantID: tenantA, destination: "connector.deploy", payload: []byte(`{"target":"edge"}`), idemKey: "deploy:a1", status: "pending", attempts: 2, lastError: "connector timeout"},
		{tenantID: tenantA, destination: "notification.expiry", payload: []byte(`{"cert":"a2"}`), idemKey: "expiry:a2", status: "delivered", attempts: 1, delivered: true},
		{tenantID: tenantB, destination: "ca.issue", payload: []byte(`{"identity_id":"b1"}`), idemKey: "issue:b1", status: "pending"},
	}
	for _, r := range rows {
		delivered := "NULL"
		if r.delivered {
			delivered = "'2026-02-01T00:00:00Z'::timestamptz"
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, attempts, last_error, delivered_at)
			VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), `+delivered+`)`,
			r.tenantID, r.destination, r.payload, r.idemKey, r.status, r.attempts, r.lastError); err != nil {
			t.Fatalf("seed outbox %s/%s: %v", r.tenantID, r.idemKey, err)
		}
	}
}

// seedBootstrapTokenContent populates agent_bootstrap_tokens across two tenants
// with a live token, an already-redeemed one, and an identity-pinned one, so the
// 0100 content case has real single-use state to protect.
func seedBootstrapTokenContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID string
		hash     string
		identity string
		used     bool
	}{
		{tenantID: tenantA, hash: "hash-a-live", identity: ""},
		{tenantID: tenantA, hash: "hash-a-used", identity: "", used: true},
		{tenantID: tenantA, hash: "hash-a-pinned", identity: "node-a-1"},
		{tenantID: tenantB, hash: "hash-b-live", identity: "edge-b-1"},
	}
	for _, r := range rows {
		used := "NULL"
		if r.used {
			used = "'2026-02-01T00:00:00Z'::timestamptz"
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO agent_bootstrap_tokens (id, tenant_id, token_hash, allowed_identity, expires_at, used_at)
			VALUES (gen_random_uuid(), $1, $2, $3, '2026-12-01T00:00:00Z'::timestamptz, `+used+`)`,
			r.tenantID, r.hash, r.identity); err != nil {
			t.Fatalf("seed bootstrap token %s/%s: %v", r.tenantID, r.hash, err)
		}
	}
}

// seedAgentRoleContent populates the agents read model across two tenants so the
// 0101 content case has a real fleet to protect.
func seedAgentRoleContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID string
		name     string
		status   string
		version  string
	}{
		{tenantID: tenantA, name: "node-a-1", status: "active", version: "1.4.0"},
		{tenantID: tenantA, name: "node-a-2", status: "stale", version: "1.3.9"},
		{tenantID: tenantB, name: "edge-b-1", status: "active", version: "1.4.0"},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO agents (id, tenant_id, name, status, version, last_seen_at)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, '2026-02-01T00:00:00Z'::timestamptz)`,
			r.tenantID, r.name, r.status, r.version); err != nil {
			t.Fatalf("seed agent %s/%s: %v", r.tenantID, r.name, err)
		}
	}
}

// seedADCSPostureContent populates the AD CS posture read model across two
// tenants so the 0105 content case has real rows to protect.
func seedADCSPostureContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows := []struct {
		tenantID string
		domain   string
		template string
		severity string
		count    int
	}{
		{tenantA, "CORP-CA", "WebServer", "", 0},
		{tenantA, "CORP-CA", "UserAuth", "critical", 2},
		{tenantB, "OTHER-CA", "WebServer", "high", 1},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO adcs_template_posture
			    (tenant_id, domain, template, worst_severity, finding_count, findings)
			VALUES ($1, $2, $3, $4, $5, '[]'::jsonb)`,
			r.tenantID, r.domain, r.template, r.severity, r.count); err != nil {
			t.Fatalf("seed adcs posture %s/%s: %v", r.domain, r.template, err)
		}
	}
}
