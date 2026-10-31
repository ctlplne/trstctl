// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A154: 0350 gives MDM SCEP policies a challenge credential reference. Rows
// from before it keep all their content and start with no reference, so no
// existing policy becomes an enabled dynamic-challenge policy by migration.
func TestMigration0350KeepsMDMPoliciesAndStartsWithNoChallengeCredential(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 350)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "35000000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mdm_scep_policies
		(id, tenant_id, name, provider, scep_profile, scep_endpoint, expected_audience, challenge_mode,
		 trust_anchor_refs, profile_guidance, enabled, rotation_version, last_rotated_at, created_at, updated_at)
		VALUES ('35000000-0000-4000-8000-0000000000a1', $1, 'intune-mobile', 'intune', 'mobile-scep',
		 '/scep/pkiclient.exe', 'https://ca.example.test/scep', 'intune-jws',
		 '{"root_ca_ref":"secret://mdm/intune/root-ca"}'::jsonb, '{"platform":"ios"}'::jsonb, true, 3,
		 '2026-10-30T00:00:00Z', '2026-10-29T00:00:00Z', '2026-10-30T00:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a pre-0350 policy: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mdm_scep_policies
		(id, tenant_id, name, provider, scep_profile, scep_endpoint, challenge_mode, enabled, created_at, updated_at)
		VALUES ('35000000-0000-4000-8000-0000000000a2', $1, 'jamf-staged', 'jamf', 'mac-scep',
		 '/scep/pkiclient.exe', 'hmac-dynamic', false, '2026-10-29T00:00:00Z', '2026-10-29T00:00:00Z')`, tenant); err != nil {
		t.Fatalf("seed a staged pre-0350 hmac-dynamic policy: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const policies = `SELECT id::text, tenant_id::text, name, provider, scep_profile, scep_endpoint, expected_audience,
		challenge_mode, trust_anchor_refs, profile_guidance, enabled, rotation_version, last_rotated_at, created_at, updated_at
		FROM mdm_scep_policies ORDER BY id`
	count, sum := checksumQuery(t, ctx, pool, policies)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, after := checksumQuery(t, ctx, pool, policies); count != 2 || n != count || after != sum {
		t.Fatalf("0350 changed MDM SCEP policies: %d/%s before, %d/%s after", count, sum, n, after)
	}
	var withRef int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mdm_scep_policies WHERE challenge_credential_ref <> ''`).Scan(&withRef); err != nil {
		t.Fatal(err)
	}
	if withRef != 0 {
		t.Fatalf("after 0350 %d policies name a challenge credential; want none", withRef)
	}
}
