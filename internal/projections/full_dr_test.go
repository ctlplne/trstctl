package projections_test

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestFullBackupRestoreIncludesPostgresState is the RESIL-001 drill: a full DR
// backup must restore BOTH sides of state, not only the event-sourced read model.
// It seeds one row in every table classified as RecoveredFromPostgresBackup,
// exports that independent state, restores a fresh event log, rebuilds projections
// from the log, imports the PostgreSQL artifact, and verifies each independent
// table is present again.
func TestFullBackupRestoreIncludesPostgresState(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL + NATS")
	}
	ctx := context.Background()
	src := newStore(t)
	srcLog := openLog(t)
	resetFullDRState(t, src)

	orch := orchestrator.NewOrchestrator(srcLog, src, orchestrator.NewOutbox(src))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "payments", "")
	if err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour)
	if _, err := orch.RecordCertificate(ctx, tenantA, store.Certificate{
		OwnerID: &owner.ID, Subject: "CN=payments.svc", Serial: "01", Fingerprint: "dr-full-fp",
		KeyAlgorithm: "ECDSA-P256", NotAfter: &expires, Source: "issued",
	}); err != nil {
		t.Fatalf("RecordCertificate: %v", err)
	}
	seedRecoveredFromPostgresTables(t, src)

	srcCounts := recoveredTableCounts(t, src)
	for _, table := range backup.RecoveredFromPostgresBackup {
		if srcCounts[table] == 0 {
			t.Fatalf("full DR fixture did not seed %s", table)
		}
	}
	srcOwners := ownerNames(t, src, tenantA)
	srcCerts := certFingerprints(t, src, tenantA)

	var eventsBuf bytes.Buffer
	if _, err := backup.WriteLog(ctx, srcLog, &eventsBuf); err != nil {
		t.Fatalf("WriteLog: %v", err)
	}
	var pgBuf bytes.Buffer
	exportSummary, err := backup.WritePostgresState(ctx, src, &pgBuf)
	if err != nil {
		t.Fatalf("WritePostgresState: %v", err)
	}
	if exportSummary.Records != len(backup.RecoveredFromPostgresBackup) {
		t.Fatalf("postgres-state export rows = %d, want one per independent table (%d)", exportSummary.Records, len(backup.RecoveredFromPostgresBackup))
	}

	dst := newStore(t)
	resetFullDRState(t, dst)
	restoredLog := openLog(t)
	if _, err := backup.RestoreLog(ctx, restoredLog, bytes.NewReader(eventsBuf.Bytes())); err != nil {
		t.Fatalf("RestoreLog: %v", err)
	}
	if err := projections.New(dst).Rebuild(ctx, restoredLog); err != nil {
		t.Fatalf("Rebuild from restored log: %v", err)
	}
	restoreSummary, err := backup.RestorePostgresState(ctx, dst, bytes.NewReader(pgBuf.Bytes()))
	if err != nil {
		t.Fatalf("RestorePostgresState: %v", err)
	}
	if restoreSummary.Records != exportSummary.Records {
		t.Fatalf("restored PostgreSQL rows = %d, want %d", restoreSummary.Records, exportSummary.Records)
	}

	if got := ownerNames(t, dst, tenantA); !sameStrings(got, srcOwners) {
		t.Errorf("owners after full restore = %v, want %v", got, srcOwners)
	}
	if got := certFingerprints(t, dst, tenantA); !sameStrings(got, srcCerts) {
		t.Errorf("certificates after full restore = %v, want %v", got, srcCerts)
	}
	dstCounts := recoveredTableCounts(t, dst)
	for _, table := range backup.RecoveredFromPostgresBackup {
		if dstCounts[table] != srcCounts[table] {
			t.Errorf("%s restored rows = %d, want %d", table, dstCounts[table], srcCounts[table])
		}
	}
}

func resetFullDRState(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	tables := append([]string(nil), backup.RecoveredFromPostgresBackup...)
	sort.Strings(tables)
	if _, err := st.SystemPool().Exec(ctx, "TRUNCATE "+quoteDRTables(tables)+" RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate independent DR tables: %v", err)
	}
}

func seedRecoveredFromPostgresTables(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	caID := "00000000-0000-0000-0000-00000000ca01"
	ceremonyID := "00000000-0000-0000-0000-00000000ce01"
	approvalResource := "identity:00000000-0000-0000-0000-00000000aa01"
	err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		statements := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, scopes, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`, []any{"00000000-0000-0000-0000-00000000a001", tenantA, "full-dr-api-token-hash", "ci", []string{"owners:read"}, now.Add(time.Hour)}},
			{`INSERT INTO agent_bootstrap_tokens (id, tenant_id, token_hash, allowed_identity, expires_at) VALUES ($1, $2, $3, $4, $5)`, []any{"00000000-0000-0000-0000-00000000a002", tenantA, "full-dr-bootstrap-hash", "edge-1", now.Add(time.Hour)}},
			{`INSERT INTO attestations (id, tenant_id, kind, evidence, verified_at) VALUES ($1, $2, $3, $4::jsonb, $5)`, []any{"00000000-0000-0000-0000-00000000a003", tenantA, "oidc", `{"issuer":"ci"}`, now}},
			{`INSERT INTO audit_checkpoints (tenant_id, boundary_seq, boundary_hash, record_count, archive_uri) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, int64(10), "full-dr-boundary", int64(3), "s3://archive/full-dr"}},
			{`INSERT INTO ca_authorities (id, tenant_id, common_name, kind, status, certificate_pem, serial, not_after, max_path_len, permitted_dns_names, ekus) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, []any{caID, tenantA, "Full DR Root", "root", "active", "-----BEGIN CERTIFICATE-----\nFULLDR\n-----END CERTIFICATE-----", "ca-01", now.Add(365 * 24 * time.Hour), 1, []string{"example.com"}, []string{"serverAuth"}}},
			{`INSERT INTO ca_key_ceremonies (id, tenant_id, purpose, threshold, status, completed_at) VALUES ($1, $2, $3, $4, $5, $6)`, []any{ceremonyID, tenantA, "root:full-dr", 2, "completed", now}},
			{`INSERT INTO ca_ceremony_approvals (tenant_id, ceremony_id, custodian, approved_at) VALUES ($1, $2, $3, $4)`, []any{tenantA, ceremonyID, "alice", now}},
			{`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed) VALUES ($1, $2, $3, $4, $5, $6)`, []any{"00000000-0000-0000-0000-00000000a005", tenantA, "connector", "target-1", "password", []byte{0xaa, 0xbb}}},
			{`INSERT INTO crypto_assets (id, tenant_id, signature, kind, location, algorithm, key_bits, strength, quantum_vulnerable, out_of_policy, reasons) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, []any{"00000000-0000-0000-0000-00000000a006", tenantA, "tls:edge:ecdsa", "tls", "edge", "ECDSA-P256", 256, "strong", false, false, []string{"baseline"}}},
			{`INSERT INTO ct_log_checkpoints (tenant_id, log_url, next_index, updated_at) VALUES ($1, $2, $3, $4)`, []any{tenantA, "https://ct.example/log", int64(42), now}},
			{`INSERT INTO ct_watched_domains (id, tenant_id, domain) VALUES ($1, $2, $3)`, []any{"00000000-0000-0000-0000-00000000a007", tenantA, "example.com"}},
			{`INSERT INTO deployment_targets (id, tenant_id, name, type, config) VALUES ($1, $2, $3, $4, $5::jsonb)`, []any{"00000000-0000-0000-0000-00000000a008", tenantA, "edge", "kubernetes", `{"namespace":"prod"}`}},
			{`INSERT INTO idempotency_keys (tenant_id, key, status, result, completed_at) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, "full-dr-idempotency", "completed", []byte(`{"ok":true}`), now}},
			{`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester, required) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, approvalResource, "issue", "requester", 2}},
			{`INSERT INTO issuance_approvals (tenant_id, resource, action, approver, approved_at) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, approvalResource, "issue", "approver-1", now}},
			{`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, attempts, next_attempt_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`, []any{tenantA, "webhook", []byte(`{"event":"full-dr"}`), "full-dr-outbox", "pending", 0, now}},
			{`INSERT INTO policy_bindings (id, tenant_id, name, policy, scope) VALUES ($1, $2, $3, $4, $5::jsonb)`, []any{"00000000-0000-0000-0000-00000000a009", tenantA, "default", "allow", `{"project":"prod"}`}},
			{`INSERT INTO secret_shares (tenant_id, token_sha256, share_id, sealed, expires_at) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, "full-dr-token-hash", "full-dr-share", []byte{0xee, 0xff}, now.Add(time.Hour)}},
			{`INSERT INTO secret_store (id, tenant_id, name, sealed, version) VALUES ($1, $2, $3, $4, $5)`, []any{"00000000-0000-0000-0000-00000000a010", tenantA, "app/db", []byte{0xcc, 0xdd}, 1}},
			{`INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, "app/db", 1, []byte{0xcc, 0xdd}, now}},
			{`INSERT INTO ssh_keys (id, tenant_id, fingerprint, key_type, comment, source, location, standing_access, orphaned) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, []any{"00000000-0000-0000-0000-00000000a011", tenantA, "SHA256:fulldr", "ssh-ed25519", "edge", "authorized_keys", "/home/app/.ssh/authorized_keys", true, false}},
		}
		for _, stmt := range statements {
			if _, err := tx.Exec(ctx, stmt.sql, stmt.args...); err != nil {
				return fmt.Errorf("seed %s: %w", stmt.sql, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed independent PostgreSQL tables: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO federation_peer_checkpoints (peer_id, source_seq, updated_at) VALUES ($1, $2, $3)`, "full-dr-peer", int64(42), now); err != nil {
		t.Fatalf("seed federation_peer_checkpoints: %v", err)
	}
}

func recoveredTableCounts(t *testing.T, st *store.Store) map[string]int {
	t.Helper()
	ctx := context.Background()
	counts := make(map[string]int, len(backup.RecoveredFromPostgresBackup))
	for _, table := range backup.RecoveredFromPostgresBackup {
		var n int
		if err := st.SystemPool().QueryRow(ctx, "SELECT count(*) FROM "+quoteDRTable(table)).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		counts[table] = n
	}
	return counts
}

func quoteDRTables(tables []string) string {
	quoted := make([]string, 0, len(tables))
	for _, table := range tables {
		quoted = append(quoted, quoteDRTable(table))
	}
	return strings.Join(quoted, ", ")
}

func quoteDRTable(table string) string {
	for _, r := range table {
		if r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			panic("unsafe backup table name in test: " + table)
		}
	}
	return `"` + table + `"`
}
