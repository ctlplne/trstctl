// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A175: 0354 lets a segment policy pin PKCS#11 token vendor roots and require
// token attestation, and lets a delegation record the token attestation it
// verified. Rows from before it keep all their content; every policy pins no
// token root and requires nothing; no delegation claims a token attestation.
func TestMigration0354KeepsEdgeRowsAndStartsWithoutTokenAttestation(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 354)
	pool, err := pgxpool.New(ctx, createFreshMigrationDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	const tenant = "35400000-0000-4000-8000-000000000001"
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
		 allowed_key_providers, renewal_enabled, renewal_window_days, updated_at, event_sequence)
		VALUES ($1, '35400000-0000-4000-8000-0000000000a1', true, ARRAY['-----BEGIN CERTIFICATE-----'],
		 ARRAY['edge.example.test'], ARRAY[]::text[], ARRAY['tpm2','pkcs11'], true, 5, '2026-11-01T00:00:00Z', 7)`, tenant); err != nil {
		t.Fatalf("seed a pre-0354 policy: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_delegations
		(tenant_id, id, segment_id, ca_id, host, common_name, serial, certificate_pem,
		 permitted_dns_domains, excluded_dns_domains, attested_key_sha256, attestation_cert_sha256,
		 csr_key_sha256, key_provider, key_storage, key_exportable, custody_assurance, status,
		 not_before, not_after, revoked_at, revoke_reason, created_at, updated_at, event_sequence)
		VALUES ($1, '35400000-0000-4000-8000-0000000000b1', '35400000-0000-4000-8000-0000000000a1',
		 '35400000-0000-4000-8000-0000000000c1', 'vault-07', 'vault edge CA', '0a1b',
		 '-----BEGIN CERTIFICATE-----', ARRAY['edge.example.test'], ARRAY[]::text[], 'aa', 'bb', 'cc',
		 'pkcs11', 'pkcs11', false, 'host_attested_operator_claim', 'active',
		 '2026-11-01T00:00:00Z', '2026-11-08T00:00:00Z', NULL, '', '2026-11-01T00:00:00Z',
		 '2026-11-01T00:00:00Z', 8)`, tenant); err != nil {
		t.Fatalf("seed a pre-0354 delegation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	const policies = `SELECT tenant_id::text, segment_id::text, enabled, attestation_roots_pem, permitted_dns_domains,
		excluded_dns_domains, allowed_key_providers, renewal_enabled, renewal_window_days, updated_at, event_sequence
		FROM edge_segment_policies ORDER BY segment_id`
	const delegations = `SELECT tenant_id::text, id::text, segment_id::text, ca_id::text, host, common_name, serial,
		certificate_pem, permitted_dns_domains, excluded_dns_domains, attested_key_sha256, attestation_cert_sha256,
		csr_key_sha256, key_provider, key_storage, key_exportable, custody_assurance, status, not_before, not_after,
		revoked_at, revoke_reason, created_at, updated_at, event_sequence FROM edge_delegations ORDER BY id`
	policyCount, policySum := checksumQuery(t, ctx, pool, policies)
	delegationCount, delegationSum := checksumQuery(t, ctx, pool, delegations)
	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	if n, sum := checksumQuery(t, ctx, pool, policies); policyCount != 1 || n != policyCount || sum != policySum {
		t.Fatalf("0354 changed segment policies: %d/%s before, %d/%s after", policyCount, policySum, n, sum)
	}
	if n, sum := checksumQuery(t, ctx, pool, delegations); delegationCount != 1 || n != delegationCount || sum != delegationSum {
		t.Fatalf("0354 changed delegations: %d/%s before, %d/%s after", delegationCount, delegationSum, n, sum)
	}
	var roots int
	var required bool
	var rootSHA, serial, pin, touch string
	if err := pool.QueryRow(ctx, `SELECT cardinality(pkcs11_attestation_roots_pem), require_pkcs11_attestation FROM edge_segment_policies`).Scan(&roots, &required); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT token_attestation_root_sha256, token_attestation_serial, token_attestation_pin_policy,
		token_attestation_touch_policy FROM edge_delegations`).Scan(&rootSHA, &serial, &pin, &touch); err != nil {
		t.Fatal(err)
	}
	if roots != 0 || required || rootSHA != "" || serial != "" || pin != "" || touch != "" {
		t.Fatalf("after 0354 roots=%d required=%v attestation=%q/%q/%q/%q; want no token attestation anywhere", roots, required, rootSHA, serial, pin, touch)
	}
	// The custody tuple stays closed: PKCS#11 is hardware-attested only with a
	// recorded token attestation, and a TPM key cannot carry one.
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	try := func(name, update string) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT tuple`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, update)
		if _, rbErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT tuple`); rbErr != nil {
			t.Fatalf("%s: %v", name, rbErr)
		}
		return err
	}
	if err := try("pkcs11 attested without a token root", `UPDATE edge_delegations SET custody_assurance = 'hardware_key_attested'`); err == nil {
		t.Fatal("a PKCS#11 key became hardware-attested without a token attestation")
	}
	if err := try("pkcs11 attested with a token root", `UPDATE edge_delegations SET custody_assurance = 'hardware_key_attested', token_attestation_root_sha256 = 'ab'`); err != nil {
		t.Fatalf("a token-attested PKCS#11 key was refused: %v", err)
	}
	if err := try("operator claim with a token root", `UPDATE edge_delegations SET token_attestation_root_sha256 = 'ab'`); err == nil {
		t.Fatal("an operator-claim PKCS#11 key carried a token attestation")
	}
	if err := try("tpm2 with a token root", `UPDATE edge_delegations SET key_provider = 'tpm2', key_storage = 'device_bound', custody_assurance = 'hardware_key_attested', token_attestation_root_sha256 = 'ab'`); err == nil {
		t.Fatal("a TPM key carried a token attestation")
	}
}
