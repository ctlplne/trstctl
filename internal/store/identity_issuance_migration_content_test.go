// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// These are historical database-content fixtures, not issuance or customer
// evidence. Both tenants deliberately have the same identity ID. No request key,
// CSR, issuance origin or ordering evidence may be guessed during an upgrade.
func seedFirstLeafMigrationContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for index, tenantID := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(tenant_id,name) VALUES($1,$2)`, tenantID, fmt.Sprintf("first-leaf-upgrade-%d", index)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO identity_transitions
			(tenant_id,identity_id,seq,from_state,to_state,event_type,reason,occurred_at)
			VALUES($1,'20500000-0000-4000-8000-000000000001',7,'requested','issued','identity.issued','historical fixture','2026-08-01T00:00:00Z')`, tenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO certificates
			(id,tenant_id,subject,fingerprint,source,issuance_idempotency_key,created_at)
			VALUES($1,$2,'legacy.example.test','same-legacy-fingerprint','import','retained-certificate-key','2026-08-01T00:00:00Z')`, uuid(tenantID, 20501), tenantID); err != nil {
			t.Fatal(err)
		}
	}
}

func firstLeafHistoricalContent(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var content string
	// Compare every old column, including NULLs and timestamps, rather than a
	// hand-selected subset that could miss an accidental metadata rewrite.
	if err := pool.QueryRow(ctx, `SELECT jsonb_build_object(
		'transitions',(SELECT jsonb_agg(to_jsonb(t)-ARRAY['idempotency_key','subject_csr_pem'] ORDER BY tenant_id,identity_id,seq) FROM identity_transitions t),
		'certificates',(SELECT jsonb_agg(to_jsonb(c)-ARRAY['recording_event_id','recording_sequence','issuance_event_id','metadata_sequence','validity_anchor'] ORDER BY tenant_id,id) FROM certificates c))::text`).Scan(&content); err != nil {
		t.Fatal(err)
	}
	return content
}

func TestMigration0205PreservesLegacyRowsWithoutInventingIssuance(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	prefix, target := splitMigrationsAtVersion(t, 205)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	seedFirstLeafMigrationContent(t, ctx, pool)
	before := firstLeafHistoricalContent(t, ctx, pool)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if after := firstLeafHistoricalContent(t, ctx, pool); after != before {
		t.Fatal("0205 changed historical row content")
	}
	var transitions, certificates int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity_transitions WHERE idempotency_key='' AND subject_csr_pem=''`).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE recording_event_id='' AND recording_sequence=0 AND issuance_event_id=''`).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if transitions != 2 || certificates != 2 {
		t.Fatalf("0205 invented provenance or lost rows: transitions=%d certificates=%d", transitions, certificates)
	}
}

func TestMigration0208PreservesMetadataWithoutInventingCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	prefix, target := splitMigrationsAtVersion(t, 208)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Seed the actual historical prefix before207 installed statement scoping,
	// then upgrade it through both metadata migrations without backfill.
	applyMigrationFiles(t, ctx, pool, prefix[:len(prefix)-1])
	seedFirstLeafMigrationContent(t, ctx, pool)
	applyMigrationFiles(t, ctx, pool, prefix[len(prefix)-1:])
	before := firstLeafHistoricalContent(t, ctx, pool)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if firstLeafHistoricalContent(t, ctx, pool) != before {
		t.Fatal("0208 changed old certificate content")
	}
	var receipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM certificate_metadata_receipts`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("invented legacy completion: %d %v", receipts, err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	// Schema/RLS fixture values are deliberately not event or customer proof.
	if _, err := tx.Exec(ctx, `INSERT INTO certificate_metadata_receipts(tenant_id,event_sequence,event_id,event_digest) VALUES($1,1,'migration-rls-fixture',$2)`, tenantA, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificate_metadata_receipts WHERE tenant_id=$1`, tenantB).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("foreign receipt visible: %d %v", receipts, err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO certificate_metadata_receipts(tenant_id,event_sequence,event_id,event_digest) VALUES($1,1,'migration-foreign-fixture',$2)`, tenantB, strings.Repeat("a", 64))
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
		t.Fatalf("foreign receipt write not denied: %v", err)
	}
}

func TestMigration0207PreservesLegacyContentAndEnforcesTenantWatermarks(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	prefix, target := splitMigrationsAtVersion(t, 207)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	seedFirstLeafMigrationContent(t, ctx, pool)
	// Existing immutable recording data predates 0207 and must also survive.
	if _, err := pool.Exec(ctx, `UPDATE certificates SET recording_event_id='retained-event',recording_sequence=9,issuance_event_id='retained-origin'`); err != nil {
		t.Fatal(err)
	}
	before := firstLeafHistoricalContent(t, ctx, pool)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if after := firstLeafHistoricalContent(t, ctx, pool); after != before {
		t.Fatal("0207 changed historical row content")
	}
	var certificates, watermarks int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE metadata_sequence=0 AND recording_event_id='retained-event' AND recording_sequence=9 AND issuance_event_id='retained-origin'`).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM certificate_metadata_watermarks`).Scan(&watermarks); err != nil {
		t.Fatal(err)
	}
	if certificates != 2 || watermarks != 0 {
		t.Fatalf("0207 guessed metadata order: certificates=%d watermarks=%d", certificates, watermarks)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificates`).Scan(&visible); err != nil || visible != 1 {
		t.Fatalf("upgraded certificate RLS: count=%d error=%v", visible, err)
	}
	// A real zero-row statement marks only the caller's tenant as unknown.
	if tag, err := tx.Exec(ctx, `UPDATE certificates SET subject=subject WHERE tenant_id=$1`, tenantB); err != nil || tag.RowsAffected() != 0 {
		t.Fatalf("foreign certificate update: rows=%d error=%v", tag.RowsAffected(), err)
	}
	var tenant string
	var sequence int64
	var unknown bool
	if err := tx.QueryRow(ctx, `SELECT tenant_id::text,latest_sequence,unknown_write FROM certificate_metadata_watermarks`).Scan(&tenant, &sequence, &unknown); err != nil || tenant != tenantA || sequence != 0 || !unknown {
		t.Fatalf("zero-row write scope: tenant=%s sequence=%d unknown=%t error=%v", tenant, sequence, unknown, err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO certificate_metadata_watermarks VALUES($1,17,false)`, tenantB)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("foreign watermark insert must fail by RLS: %v", err)
	}
}

func TestMigration0206ActualRunnerUpgradesPopulated0205(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	prefix, _ := splitMigrationsAtVersion(t, 206)
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	seedFirstLeafMigrationContent(t, ctx, pool)
	if _, err := pool.Exec(ctx, `UPDATE identity_transitions SET idempotency_key='same-key-in-both-tenants',subject_csr_pem='historical-public-CSR-fixture'`); err != nil {
		t.Fatal(err)
	}
	// Reproduce the supported pre-checksum ledger, recording only migrations
	// actually executed above. Migrate must adopt them and execute 0206 itself.
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations(version bigint PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range prefix {
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, migration.version); err != nil {
			t.Fatal(err)
		}
	}
	before := firstLeafHistoricalContent(t, ctx, pool)
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	for attempt := 0; attempt < 2; attempt++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("actual runner attempt %d: %v", attempt, err)
		}
		assertIndexReady(t, ctx, pool, "identity_transitions_issuance_result_idx")
		if after := firstLeafHistoricalContent(t, ctx, pool); after != before {
			t.Fatal("runner changed populated legacy content")
		}
		var preserved int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity_transitions WHERE idempotency_key='same-key-in-both-tenants' AND subject_csr_pem='historical-public-CSR-fixture'`).Scan(&preserved); err != nil || preserved != 2 {
			t.Fatalf("runner changed retained transition material: count=%d error=%v", preserved, err)
		}
		for _, version := range []int{205, 206, 207} {
			_, migration := splitMigrationsAtVersion(t, version)
			var name, checksum string
			if err := pool.QueryRow(ctx, `SELECT name,checksum FROM schema_migrations WHERE version=$1`, version).Scan(&name, &checksum); err != nil {
				t.Fatal(err)
			}
			canonical := strings.TrimRight(strings.ReplaceAll(migration.body, "\r\n", "\n"), "\n")
			if name != migration.name || checksum != "sha256:"+crypto.SHA256Hex([]byte(canonical)) {
				t.Fatalf("runner recorded a different migration %d: name=%s checksum=%s", version, name, checksum)
			}
		}
	}
}
