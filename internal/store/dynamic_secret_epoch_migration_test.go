// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

func TestMigration0156CanonicalizesPendingDynamicSecretOutboxCommandsAUD108(t *testing.T) {
	ctx := context.Background()
	prefix, target := splitMigrationsAtVersion(t, 156)
	if target.name != "0156_dynamic_secret_tenant_epoch_recovery.sql" || target.noTx {
		t.Fatalf("migration 0156 classification = name:%q no_tx:%t", target.name, target.noTx)
	}
	dsn := createFreshMigrationDatabase(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect fresh 0156 content database: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigrationFiles(t, ctx, pool, prefix)

	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (tenant_id, name, event_seq) VALUES ($1, 'migration-0156', 10)`,
		tenantA); err != nil {
		t.Fatalf("seed migration tenant: %v", err)
	}
	const (
		issueLeaseID  = "lease-migration-0156-issue"
		revokeLeaseID = "lease-migration-0156-revoke"
		issuedAt      = "2026-08-11T12:00:00Z"
		expiresAt     = "2026-08-11T13:00:00Z"
		hardExpiresAt = "2026-08-11T14:00:00Z"
	)
	issuePayload := []byte(`{"id":"lease-migration-0156-issue","idempotency_key":"migration-0156-issue","request_binding":"sha256:migration-0156-issue","provider":"postgres-production","role":"reader","expires_at":"2026-08-11T13:00:00Z","hard_expires_at":"2026-08-11T14:00:00Z","sealed_preparation":"cHJlcGFyZWQ="}`)
	revokeIssuePayload := []byte(`{"id":"lease-migration-0156-revoke","idempotency_key":"migration-0156-revoke-issue","request_binding":"sha256:migration-0156-revoke-issue","provider":"postgres-production","role":"reader","expires_at":"2026-08-11T13:00:00Z","hard_expires_at":"2026-08-11T14:00:00Z"}`)
	revokePayload := []byte(`{"LeaseID":"lease-migration-0156-revoke","Provider":"postgres-production","BackendRef":"backend-migration-0156"}`)

	insertOutbox := func(destination, key, status string, payload []byte) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key, status)
			VALUES ($1, $2, 'dynsecret.provider:postgres-production', $3, $4, $5)
			RETURNING id`, tenantA, destination, payload, key, status).Scan(&id); err != nil {
			t.Fatalf("seed %s outbox: %v", destination, err)
		}
		return id
	}
	issueOutboxID := insertOutbox("dynsecret.issue", "dynsecret.issue:"+issueLeaseID, "pending", issuePayload)
	revokeIssueOutboxID := insertOutbox("dynsecret.issue", "dynsecret.issue:"+revokeLeaseID, "delivered", revokeIssuePayload)
	revokeOutboxID := insertOutbox("dynsecret.revoke", "dynsecret.revoke:"+revokeLeaseID, "pending", revokePayload)

	if _, err := pool.Exec(ctx, `
		INSERT INTO dynamic_secret_leases
		       (tenant_id, id, idempotency_key, request_binding, provider, role,
		        backend_ref, sealed_credential, sealed_preparation, state,
		        issue_outbox_id, revocation_status, issued_at, expires_at,
		        hard_expires_at, updated_at)
		VALUES ($1, $2, 'migration-0156-issue', 'sha256:migration-0156-issue',
		        'postgres-production', 'reader', '', ''::bytea, 'prepared'::bytea,
		        'pending', $3, 'none', $4, $5, $6, $4)`,
		tenantA, issueLeaseID, issueOutboxID, issuedAt, expiresAt, hardExpiresAt); err != nil {
		t.Fatalf("seed pending issue lease: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO dynamic_secret_leases
		       (tenant_id, id, idempotency_key, request_binding, provider, role,
		        backend_ref, sealed_credential, sealed_preparation, state,
		        issue_outbox_id, revocation_status, revoke_outbox_id, issued_at,
		        expires_at, hard_expires_at, revoked_at, updated_at)
		VALUES ($1, $2, 'migration-0156-revoke-issue', 'sha256:migration-0156-revoke-issue',
		        'postgres-production', 'reader', 'backend-migration-0156',
		        ''::bytea, ''::bytea, 'revoked', $3, 'pending', $4,
		        $5, $6, $7, $5, $5)`,
		tenantA, revokeLeaseID, revokeIssueOutboxID, revokeOutboxID,
		issuedAt, expiresAt, hardExpiresAt); err != nil {
		t.Fatalf("seed pending revoke lease: %v", err)
	}

	applyMigrationFiles(t, ctx, pool, []migrationFile{target})
	var epoch string
	if err := pool.QueryRow(ctx,
		`SELECT epoch_id::text FROM application_secret_tenant_epochs WHERE tenant_id = $1`,
		tenantA).Scan(&epoch); err != nil {
		t.Fatalf("load migrated dynamic-secret epoch: %v", err)
	}
	if epoch == "" {
		t.Fatal("migration produced an empty dynamic-secret epoch")
	}

	assertCommand := func(outboxID int64, wantKey string, legacy []byte) {
		t.Helper()
		var gotKey string
		var gotPayload []byte
		if err := pool.QueryRow(ctx,
			`SELECT idempotency_key, payload FROM outbox WHERE tenant_id = $1 AND id = $2`,
			tenantA, outboxID).Scan(&gotKey, &gotPayload); err != nil {
			t.Fatalf("load migrated outbox %d: %v", outboxID, err)
		}
		wantPayload := append([]byte(`{"tenant_epoch":"`+epoch+`",`), legacy[1:]...)
		if gotKey != wantKey || string(gotPayload) != string(wantPayload) {
			t.Fatalf("migrated outbox %d = key:%q payload:%s, want key:%q payload:%s",
				outboxID, gotKey, gotPayload, wantKey, wantPayload)
		}
	}
	assertCommand(issueOutboxID,
		store.DynamicSecretIssueOutboxIdempotencyKey(epoch, issueLeaseID), issuePayload)
	assertCommand(revokeOutboxID,
		store.DynamicSecretRevokeOutboxIdempotencyKey(epoch, revokeLeaseID), revokePayload)

	var preparationDigest string
	if err := pool.QueryRow(ctx,
		`SELECT preparation_digest FROM dynamic_secret_leases WHERE tenant_id = $1 AND id = $2`,
		tenantA, issueLeaseID).Scan(&preparationDigest); err != nil {
		t.Fatal(err)
	}
	if preparationDigest != crypto.SHA256Hex([]byte("prepared")) {
		t.Fatalf("migrated preparation digest = %q, want retained ciphertext proof", preparationDigest)
	}
}
