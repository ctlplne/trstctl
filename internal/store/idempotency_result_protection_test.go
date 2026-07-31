// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// TestIdempotencyResultMigrationIsRLSScopedResumableAndLeavesNoPlaintext is the
// named two-tenant PostgreSQL proof for S-3def6339. It includes both historical
// codecs and inspects the database bytes directly after a one-row-batch resume.
func TestIdempotencyResultMigrationIsRLSScopedResumableAndLeavesNoPlaintext(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: tenantID, EventSeq: 1}); err != nil {
			t.Fatalf("UpsertTenant(%s): %v", tenantID, err)
		}
	}

	keyMaterial := bytes.Repeat([]byte{0x61}, 32)
	deployment, err := seal.NewLocalKEK(keyMaterial)
	secret.Wipe(keyMaterial)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	defer deployment.Destroy()
	registry, err := tenantseal.NewLocalWrapperRegistry(nil)
	if err != nil {
		t.Fatalf("NewLocalWrapperRegistry: %v", err)
	}
	access, err := tenantseal.NewAccess(s, deployment, registry)
	if err != nil {
		t.Fatalf("NewAccess: %v", err)
	}
	protector, err := tenantseal.NewResultProtector(access)
	if err != nil {
		t.Fatalf("NewResultProtector: %v", err)
	}
	migrator, err := tenantseal.NewResultMigrator(s, protector, 1)
	if err != nil {
		t.Fatalf("NewResultMigrator: %v", err)
	}

	rawCanary := []byte("api-token-canary-A")
	dynamicPlaintext := []byte("database-password-canary-A")
	dynamicAAD := []byte("historical-dynamic-lease")
	dynamicEnvelope, err := seal.Seal(deployment, dynamicPlaintext, dynamicAAD)
	if err != nil {
		t.Fatalf("seal historical dynamic lease: %v", err)
	}
	defer secret.Wipe(dynamicEnvelope)
	tenantBCanary := []byte("private-key-canary-B")

	insert := func(tenantID, key, binding, codec string, result []byte) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO idempotency_keys
				       (tenant_id, key, status, request_binding, result_codec, result, completed_at)
				 VALUES ($1, $2, 'completed', $3, $4, $5, now())`,
				tenantID, key, binding, codec, result)
			return err
		}); err != nil {
			t.Fatalf("insert %s/%s: %v", tenantID, key, err)
		}
	}
	insert(tenantA, "a-raw", "binding-a", orchestrator.ResultCodecRawV0, rawCanary)
	insert(tenantA, "b-dynamic", "binding-b", orchestrator.ResultCodecSealedDynamicLeaseV1, dynamicEnvelope)
	insert(tenantB, "a-raw", "binding-a", orchestrator.ResultCodecRawV0, tenantBCanary)

	statusA, err := migrator.MigrateTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("MigrateTenant(A): %v", err)
	}
	if statusA.RemainingLegacy() != 0 || statusA.SealedRowV1 != 2 {
		t.Fatalf("tenant A status = %+v, want 2 sealed and zero legacy", statusA)
	}
	statusB, err := s.IdempotencyResultProtectionStatus(ctx, tenantB)
	if err != nil {
		t.Fatalf("tenant B status: %v", err)
	}
	if statusB.RawV0 != 1 || statusB.SealedRowV1 != 0 {
		t.Fatalf("tenant B changed during tenant A migration: %+v", statusB)
	}

	type protectedRow struct {
		key, binding, codec string
		result              []byte
	}
	rows, err := s.SystemPool().Query(ctx,
		`SELECT key, request_binding, result_codec, result
		   FROM idempotency_keys
		  WHERE tenant_id = $1
		  ORDER BY key`, tenantA)
	if err != nil {
		t.Fatalf("inspect tenant A rows: %v", err)
	}
	var got []protectedRow
	for rows.Next() {
		var row protectedRow
		if err := rows.Scan(&row.key, &row.binding, &row.codec, &row.result); err != nil {
			rows.Close()
			t.Fatalf("scan protected row: %v", err)
		}
		got = append(got, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("read protected rows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("tenant A rows = %d, want 2", len(got))
	}
	for _, row := range got {
		defer secret.Wipe(row.result)
		if row.codec != orchestrator.ResultCodecSealedRowV1 {
			t.Fatalf("row %s codec = %q", row.key, row.codec)
		}
		if bytes.Contains(row.result, rawCanary) || bytes.Contains(row.result, dynamicPlaintext) {
			t.Fatalf("row %s retains plaintext canary", row.key)
		}
	}
	rawOpened, err := protector.Open(ctx, tenantA, got[0].key, got[0].binding, got[0].codec, got[0].result)
	if err != nil {
		t.Fatalf("open migrated raw row: %v", err)
	}
	defer secret.Wipe(rawOpened)
	if !bytes.Equal(rawOpened, rawCanary) {
		t.Fatalf("opened raw = %q", rawOpened)
	}
	dynamicOpened, err := protector.Open(ctx, tenantA, got[1].key, got[1].binding, got[1].codec, got[1].result)
	if err != nil {
		t.Fatalf("open migrated dynamic row: %v", err)
	}
	defer secret.Wipe(dynamicOpened)
	if !bytes.Equal(dynamicOpened, dynamicEnvelope) {
		t.Fatal("migrated dynamic row did not preserve its authenticated inner envelope")
	}
	if _, err := protector.Open(ctx, tenantB, got[0].key, got[0].binding, got[0].codec, got[0].result); err == nil {
		t.Fatal("tenant B opened tenant A result copied across the RLS boundary")
	}

	statuses, err := migrator.MigrateAll(ctx)
	if err != nil {
		t.Fatalf("MigrateAll resume: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("MigrateAll statuses = %d, want 2", len(statuses))
	}
	statusB, err = s.IdempotencyResultProtectionStatus(ctx, tenantB)
	if err != nil {
		t.Fatalf("tenant B final status: %v", err)
	}
	if statusB.RemainingLegacy() != 0 || statusB.SealedRowV1 != 1 {
		t.Fatalf("tenant B final status = %+v", statusB)
	}
}
