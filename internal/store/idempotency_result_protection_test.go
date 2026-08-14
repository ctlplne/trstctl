// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
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
	t.Cleanup(func() {
		if _, err := s.SystemPool().Exec(context.Background(), `
			ALTER TABLE idempotency_keys
			    DROP CONSTRAINT IF EXISTS idempotency_keys_result_sealed_floor_chk,
			    ALTER COLUMN result_codec SET DEFAULT 'raw-v0'`); err != nil {
			t.Errorf("restore pre-ratchet idempotency schema: %v", err)
		}
	})
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
	migrator, err := tenantseal.NewResultMigrator(s, protector, 1, true)
	if err != nil {
		t.Fatalf("NewResultMigrator: %v", err)
	}

	rawCanaries := map[string][]byte{
		"a-share":      []byte("share-value-token-canary-A"),
		"b-api-token":  []byte("api-token-canary-A"),
		"c-enrollment": []byte("enrollment-token-canary-A"),
		"d-pki-key":    []byte("pki-private-key-canary-A"),
		"e-pam-dsn":    []byte("postgres://pam-password-canary-A@db.internal"),
		"f-ephemeral":  []byte("ephemeral-key-canary-A"),
		"g-vault":      []byte("vault-pki-transit-output-canary-A"),
	}
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
	for key, canary := range rawCanaries {
		insert(tenantA, key, "binding-"+key, orchestrator.ResultCodecRawV0, canary)
	}
	insert(tenantA, "h-dynamic", "binding-h-dynamic", orchestrator.ResultCodecSealedDynamicLeaseV1, dynamicEnvelope)
	insert(tenantB, "a-raw", "binding-a", orchestrator.ResultCodecRawV0, tenantBCanary)

	statusA, err := migrator.MigrateTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("MigrateTenant(A): %v", err)
	}
	if statusA.RemainingLegacy() != 0 || statusA.SealedRowV1 != int64(len(rawCanaries)+1) {
		t.Fatalf("tenant A status = %+v, want %d sealed and zero legacy", statusA, len(rawCanaries)+1)
	}
	floorEnabled, err := s.IdempotencyResultSealedFloorEnabled(ctx)
	if err != nil {
		t.Fatalf("inspect floor before fleet migration: %v", err)
	}
	if floorEnabled {
		t.Fatal("sealed-only floor enabled before fleet migration completed")
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
	if len(got) != len(rawCanaries)+1 {
		t.Fatalf("tenant A rows = %d, want %d", len(got), len(rawCanaries)+1)
	}
	for _, row := range got {
		defer secret.Wipe(row.result)
		if row.codec != orchestrator.ResultCodecSealedRowV1 {
			t.Fatalf("row %s codec = %q", row.key, row.codec)
		}
		for _, canary := range rawCanaries {
			if bytes.Contains(row.result, canary) {
				t.Fatalf("row %s retains plaintext canary", row.key)
			}
		}
		if bytes.Contains(row.result, dynamicPlaintext) {
			t.Fatalf("row %s retains dynamic plaintext canary", row.key)
		}
		opened, err := protector.Open(ctx, tenantA, row.key, row.binding, row.codec, row.result)
		if err != nil {
			t.Fatalf("open migrated row %s: %v", row.key, err)
		}
		want, raw := rawCanaries[row.key]
		if !raw {
			want = dynamicEnvelope
		}
		if !bytes.Equal(opened, want) {
			secret.Wipe(opened)
			t.Fatalf("opened row %s did not preserve its exact result", row.key)
		}
		secret.Wipe(opened)
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
	floorEnabled, err = s.IdempotencyResultSealedFloorEnabled(ctx)
	if err != nil {
		t.Fatalf("inspect floor after fleet migration: %v", err)
	}
	if !floorEnabled {
		t.Fatal("sealed-only floor not reported after fleet migration")
	}
	statusB, err = s.IdempotencyResultProtectionStatus(ctx, tenantB)
	if err != nil {
		t.Fatalf("tenant B final status: %v", err)
	}
	if statusB.RemainingLegacy() != 0 || statusB.SealedRowV1 != 1 {
		t.Fatalf("tenant B final status = %+v", statusB)
	}

	var artifact bytes.Buffer
	if _, err := backup.WritePostgresState(ctx, s, &artifact); err != nil {
		t.Fatalf("write PostgreSQL backup: %v", err)
	}
	for name, canary := range rawCanaries {
		if bytes.Contains(artifact.Bytes(), canary) || bytes.Contains(artifact.Bytes(), []byte(hex.EncodeToString(canary))) {
			t.Fatalf("PostgreSQL backup exposes %s plaintext canary", name)
		}
	}
	if bytes.Contains(artifact.Bytes(), dynamicPlaintext) || bytes.Contains(artifact.Bytes(), []byte(hex.EncodeToString(dynamicPlaintext))) {
		t.Fatal("PostgreSQL backup exposes historical dynamic-lease plaintext canary")
	}
	if _, err := backup.RestorePostgresState(ctx, s, bytes.NewReader(artifact.Bytes())); err != nil {
		t.Fatalf("restore PostgreSQL backup: %v", err)
	}
	statusA, err = s.IdempotencyResultProtectionStatus(ctx, tenantA)
	if err != nil {
		t.Fatalf("tenant A status after restore: %v", err)
	}
	if statusA.RemainingLegacy() != 0 || statusA.SealedRowV1 != int64(len(rawCanaries)+1) {
		t.Fatalf("tenant A restored status = %+v", statusA)
	}
	restoredRows, err := s.SystemPool().Query(ctx,
		`SELECT key, request_binding, result_codec, result
		   FROM idempotency_keys
		  WHERE tenant_id = $1
		  ORDER BY key`, tenantA)
	if err != nil {
		t.Fatalf("inspect restored tenant A rows: %v", err)
	}
	restoredCount := 0
	for restoredRows.Next() {
		var row protectedRow
		if err := restoredRows.Scan(&row.key, &row.binding, &row.codec, &row.result); err != nil {
			restoredRows.Close()
			t.Fatalf("scan restored protected row: %v", err)
		}
		opened, err := protector.Open(ctx, tenantA, row.key, row.binding, row.codec, row.result)
		secret.Wipe(row.result)
		if err != nil {
			restoredRows.Close()
			t.Fatalf("open restored row %s: %v", row.key, err)
		}
		want, raw := rawCanaries[row.key]
		if !raw {
			want = dynamicEnvelope
		}
		if !bytes.Equal(opened, want) {
			secret.Wipe(opened)
			restoredRows.Close()
			t.Fatalf("restored row %s did not preserve its exact result", row.key)
		}
		secret.Wipe(opened)
		restoredCount++
	}
	restoredRows.Close()
	if err := restoredRows.Err(); err != nil {
		t.Fatalf("read restored protected rows: %v", err)
	}
	if restoredCount != len(rawCanaries)+1 {
		t.Fatalf("restored tenant A rows = %d, want %d", restoredCount, len(rawCanaries)+1)
	}

	insertAfterFloor := func(key, codec string, result []byte, includeCodec bool) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if !includeCodec {
				_, err := tx.Exec(ctx,
					`INSERT INTO idempotency_keys
					       (tenant_id, key, status, request_binding, result, completed_at)
					 VALUES ($1, $2, 'completed', '', $3, now())`,
					tenantA, key, result)
				return err
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO idempotency_keys
				       (tenant_id, key, status, request_binding, result_codec, result, completed_at)
				 VALUES ($1, $2, 'completed', '', $3, $4, now())`,
				tenantA, key, codec, result)
			return err
		})
	}
	if err := insertAfterFloor("blocked-explicit-raw", orchestrator.ResultCodecRawV0, []byte("raw"), true); err == nil {
		t.Fatal("sealed-only floor accepted an explicit raw-v0 completed result")
	}
	if err := insertAfterFloor("blocked-default-raw", "", []byte("raw"), false); err == nil {
		t.Fatal("sealed-only floor mislabeled raw bytes through the column default")
	}
	codec, protected, err := protector.Protect(ctx, tenantA, "allowed-sealed", "", []byte("protected"))
	if err != nil {
		t.Fatalf("protect row after floor: %v", err)
	}
	defer secret.Wipe(protected)
	if err := insertAfterFloor("allowed-sealed", codec, protected, true); err != nil {
		t.Fatalf("sealed-only floor rejected protected result: %v", err)
	}
}
