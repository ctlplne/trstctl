// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration0227PreservesUnknownIssuanceReceipts(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 227)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	if _, err := pool.Exec(ctx, `INSERT INTO certificate_metadata_receipts
		(tenant_id,event_sequence,event_id,event_digest) VALUES($1,1,'retained-event',$2)`, tenantA, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (tenant_id,name) VALUES($1,'upgrade-fixture')`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ca_issued_certs (tenant_id,ca_id,serial,issued_at) VALUES($1,$2,'legacy-leaf',now())`, tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	var legacyKnown, emptyKnown bool
	if err := pool.QueryRow(ctx, `SELECT responder_issuance_history_known FROM tenants WHERE tenant_id=$1`, tenantA).Scan(&legacyKnown); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT responder_issuance_history_known FROM tenants WHERE tenant_id=$1`, tenantB).Scan(&emptyKnown); err != nil {
		t.Fatal(err)
	}
	if legacyKnown || !emptyKnown {
		t.Fatalf("migration history guards legacy=%t empty=%t, want false/true", legacyKnown, emptyKnown)
	}

	var status, fingerprint *string
	var intact bool
	if err := pool.QueryRow(ctx, `SELECT issuance_status,issuance_fingerprint,
		event_id='retained-event' AND event_digest=$2 AND issuance_time IS NULL
		FROM certificate_metadata_receipts WHERE tenant_id=$1`, tenantA, strings.Repeat("a", 64)).Scan(&status, &fingerprint, &intact); err != nil {
		t.Fatal(err)
	}
	if status != nil || fingerprint != nil || !intact {
		t.Fatal("migration invented an issuance fact or changed the retained completion receipt")
	}
	for _, assignment := range []string{
		"issuance_status='mint'",
		"issuance_status='not_mint',issuance_time=now()",
		"issuance_fingerprint='leaf',issuance_time=now()",
		"issuance_status='unknown-status'",
	} {
		if _, err := pool.Exec(ctx, `UPDATE certificate_metadata_receipts SET `+assignment+` WHERE tenant_id=$1`, tenantA); err == nil {
			t.Fatalf("incomplete or contradictory issuance shape accepted: %s", assignment)
		}
	}
}

func TestMigration0229BuildsReceiptIndexWithRetryAndRetainedFacts(t *testing.T) {
	ctx := t.Context()
	prefix, target := splitMigrationsAtVersion(t, 229)
	if !target.noTx {
		t.Fatal("receipt index must run outside a transaction")
	}
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO certificate_metadata_receipts
			(tenant_id,event_sequence,event_id,event_digest,issuance_status,issuance_fingerprint,issuance_time)
			VALUES($1,1,'same-event',repeat('a',64),'mint','same-leaf','2026-09-01T00:00:00Z')`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	// Repeating an unledgered completed build must converge and retain facts.
	for range 2 {
		applyMigrationFiles(t, ctx, pool, []migrationFile{target})
		assertIndexReady(t, ctx, pool, "certificate_receipt_issuance_origin")
	}
	for _, tenant := range []string{tenantA, tenantB} {
		var intact bool
		if err := pool.QueryRow(ctx, `SELECT event_sequence=1 AND event_id='same-event'
			AND event_digest=repeat('a',64) AND issuance_status='mint' AND issuance_fingerprint='same-leaf'
			AND issuance_time='2026-09-01T00:00:00Z'::timestamptz
			FROM certificate_metadata_receipts WHERE tenant_id=$1`, tenant).Scan(&intact); err != nil || !intact {
			t.Fatalf("index retry changed retained issuance facts: intact=%t err=%v", intact, err)
		}
	}
}

func TestIssuanceBackfillProbeInspectsEachLiveTenantUnderRLS(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	seedTwoTenants(t, s)
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO certificate_metadata_receipts
				(tenant_id,event_sequence,event_id,event_digest,issuance_status)
				VALUES($1,1,'same-event',repeat('a',64),'not_mint')`, tenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertNeeded := func(want bool) {
		t.Helper()
		got, err := s.CertificateIssuanceReceiptsNeedBackfill(ctx)
		if err != nil || got != want {
			t.Fatalf("backfill needed=%t want=%t err=%v", got, want, err)
		}
	}
	assertNeeded(false)
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificate_metadata_receipts SET issuance_status=NULL WHERE tenant_id=$1`, tenantB)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	assertNeeded(true)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificate_metadata_receipts WHERE tenant_id=$1`, tenantB).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("application role exposed another tenant's receipts")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OffboardTenant(ctx, tenantB); err != nil {
		t.Fatal(err)
	}
	assertNeeded(false)
	// The registry error must remain visible, never become an empty-history pass.
	s.Close()
	if _, err := s.CertificateIssuanceReceiptsNeedBackfill(ctx); err == nil {
		t.Fatal("closed registry connection reported successful empty history")
	}
}
