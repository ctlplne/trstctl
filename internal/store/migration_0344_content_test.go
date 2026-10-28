// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A220: 0344 gives segment policies a renewal setting and delegations a link
// to the one they renewed. Rows from before it keep all their content, every
// policy starts with renewal off, and no delegation claims to renew another.
func TestMigration0344KeepsEdgePoliciesAndStartsWithRenewalOff(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 344)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "34400000-0000-4000-8000-000000000001"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_segment_policies
		(tenant_id, segment_id, enabled, attestation_roots_pem, permitted_dns_domains, excluded_dns_domains,
		 allowed_key_providers, updated_at, event_sequence)
		VALUES ($1, '34400000-0000-4000-8000-0000000000a1', true, ARRAY['-----BEGIN CERTIFICATE-----'],
		 ARRAY['edge.example.test'], ARRAY[]::text[], ARRAY['tpm2'], '2026-10-28T00:00:00Z', 7)`, tenant); err != nil {
		t.Fatalf("seed a pre-0344 policy: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_delegations
		(tenant_id, id, segment_id, ca_id, host, common_name, serial, certificate_pem,
		 permitted_dns_domains, excluded_dns_domains, attested_key_sha256, attestation_cert_sha256,
		 csr_key_sha256, status, not_before, not_after, revoked_at, revoke_reason, created_at, updated_at, event_sequence)
		VALUES ($1, '34400000-0000-4000-8000-0000000000b1', '34400000-0000-4000-8000-0000000000a1',
		 '34400000-0000-4000-8000-0000000000c1', 'bunker-01', 'bunker edge CA', '0a1b',
		 '-----BEGIN CERTIFICATE-----', ARRAY['edge.example.test'], ARRAY[]::text[], 'aa', 'bb', 'aa',
		 'active', '2026-10-28T00:00:00Z', '2026-11-04T00:00:00Z', NULL, '', '2026-10-28T00:00:00Z',
		 '2026-10-28T00:00:00Z', 8)`, tenant); err != nil {
		t.Fatalf("seed a pre-0344 delegation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const policies = `SELECT tenant_id::text, segment_id::text, enabled, attestation_roots_pem, permitted_dns_domains,
		excluded_dns_domains, allowed_key_providers, updated_at, event_sequence FROM edge_segment_policies ORDER BY segment_id`
	const delegations = `SELECT tenant_id::text, id::text, segment_id::text, ca_id::text, host, common_name, serial,
		certificate_pem, permitted_dns_domains, excluded_dns_domains, attested_key_sha256, attestation_cert_sha256,
		csr_key_sha256, key_provider, key_storage, key_exportable, custody_assurance, status, not_before, not_after,
		revoked_at, revoke_reason, created_at, updated_at, event_sequence FROM edge_delegations ORDER BY id`
	policyCount, policySum := checksumQuery(t, ctx, pool, policies)
	delegationCount, delegationSum := checksumQuery(t, ctx, pool, delegations)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, sum := checksumQuery(t, ctx, pool, policies); policyCount != 1 || n != policyCount || sum != policySum {
		t.Fatalf("0344 changed segment policies: %d/%s before, %d/%s after", policyCount, policySum, n, sum)
	}
	if n, sum := checksumQuery(t, ctx, pool, delegations); delegationCount != 1 || n != delegationCount || sum != delegationSum {
		t.Fatalf("0344 changed delegations: %d/%s before, %d/%s after", delegationCount, delegationSum, n, sum)
	}
	var renewal bool
	var window int
	var renewedFromNull bool
	if err := pool.QueryRow(ctx, `SELECT renewal_enabled, renewal_window_days FROM edge_segment_policies`).Scan(&renewal, &window); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT renewed_from IS NULL FROM edge_delegations`).Scan(&renewedFromNull); err != nil {
		t.Fatal(err)
	}
	if renewal || window != 0 || !renewedFromNull {
		t.Fatalf("after 0344 renewal=%v window=%d renewed_from null=%v; want renewal off and no link", renewal, window, renewedFromNull)
	}
}
