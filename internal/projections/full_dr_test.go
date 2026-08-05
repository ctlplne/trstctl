// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/events"
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

// TestFullRestoreFinalRebuildHealsPrivacyOperationMissingFromPostgresCut pins
// the append-ACK/projection-failure recovery boundary. The event log can contain
// the durable privacy receiver's source event while the paired PostgreSQL
// snapshot still has no receiver row. A preliminary rebuild heals that row, but
// restoring the older PostgreSQL artifact replaces it again. Full restore must
// therefore finish with another rebuild after the PostgreSQL import.
func TestFullRestoreFinalRebuildHealsPrivacyOperationMissingFromPostgresCut(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL + NATS")
	}
	ctx := context.Background()
	src := newStore(t)
	resetFullDRState(t, src)
	srcLog := openLog(t)

	const (
		eventID        = "full-dr-privacy-crash-event"
		operationID    = "full-dr-privacy-crash-operation"
		requestBinding = "sha256:full-dr-privacy-crash-command"
		subjectRef     = "subject:full-dr-crash"
	)
	payload, err := json.Marshal(projections.PrivacySubjectErased{
		OperationID:    operationID,
		RequestBinding: requestBinding,
		SubjectRef:     subjectRef,
		Reason:         "approved erasure",
		Counts:         map[string]int{"owners": 1},
	})
	if err != nil {
		t.Fatalf("marshal privacy erasure event: %v", err)
	}
	sourceEvent, err := srcLog.Append(ctx, events.Event{
		ID:            eventID,
		Type:          projections.EventPrivacySubjectErased,
		TenantID:      tenantA,
		SchemaVersion: projections.PrivacySubjectErasedEventSchemaVersion,
		Time:          time.Now().UTC(),
		Data:          payload,
	})
	if err != nil {
		t.Fatalf("append privacy erasure event: %v", err)
	}
	if _, err := src.GetPrivacySubjectErasureOperationByEventID(ctx, tenantA, eventID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("source receiver before projection error = %v, want pgx.ErrNoRows", err)
	}

	var eventsBuf bytes.Buffer
	if _, err := backup.WriteLog(ctx, srcLog, &eventsBuf); err != nil {
		t.Fatalf("WriteLog: %v", err)
	}
	var pgBuf bytes.Buffer
	pgSummary, err := backup.WritePostgresState(ctx, src, &pgBuf)
	if err != nil {
		t.Fatalf("WritePostgresState: %v", err)
	}
	if got := pgSummary.Tables["privacy_subject_erasure_operations"]; got != 0 {
		t.Fatalf("crash-shaped PostgreSQL cut has %d privacy receiver rows, want 0", got)
	}

	dst := newStore(t)
	resetFullDRState(t, dst)
	restoredLog := openLog(t)
	if _, err := backup.RestoreLog(ctx, restoredLog, bytes.NewReader(eventsBuf.Bytes())); err != nil {
		t.Fatalf("RestoreLog: %v", err)
	}
	if err := projections.New(dst).Rebuild(ctx, restoredLog); err != nil {
		t.Fatalf("preliminary Rebuild: %v", err)
	}
	if _, err := dst.GetPrivacySubjectErasureOperationByEventID(ctx, tenantA, eventID); err != nil {
		t.Fatalf("preliminary rebuild did not heal receiver: %v", err)
	}

	if _, err := backup.RestorePostgresState(ctx, dst, bytes.NewReader(pgBuf.Bytes())); err != nil {
		t.Fatalf("RestorePostgresState: %v", err)
	}
	if _, err := dst.GetPrivacySubjectErasureOperationByEventID(ctx, tenantA, eventID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("PostgreSQL import receiver error = %v, want pgx.ErrNoRows before final rebuild", err)
	}

	if err := projections.New(dst).Rebuild(ctx, restoredLog); err != nil {
		t.Fatalf("final Rebuild after PostgreSQL import: %v", err)
	}
	got, err := dst.GetPrivacySubjectErasureOperationByEventID(ctx, tenantA, eventID)
	if err != nil {
		t.Fatalf("final rebuild did not heal receiver: %v", err)
	}
	if got.OperationID != operationID || got.RequestBinding != requestBinding ||
		got.SubjectRef != subjectRef || got.EventSequence != sourceEvent.Sequence {
		t.Fatalf("healed receiver = %+v, want exact event-derived operation", got)
	}
}

func TestExactRestoreRebuildCheckpointCoversTrailingAndAllGapHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL + NATS")
	}
	for _, tc := range []struct {
		name            string
		keepFirstTenant bool
		wantTenants     int
	}{
		{name: "trailing gap", keepFirstTenant: true, wantTenants: 2},
		{name: "all gap", wantTenants: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srcLog := openLog(t)
			if tc.keepFirstTenant {
				if _, err := srcLog.Append(ctx, events.Event{
					Type: projections.EventTenantRegistered, TenantID: tenantA,
					Data: tenantRegistered("kept-before-gap"),
				}); err != nil {
					t.Fatalf("append retained event: %v", err)
				}
			}
			pruned, err := srcLog.Append(ctx, events.Event{
				Type: projections.EventTenantRegistered, TenantID: tenantB,
				Data: tenantRegistered("deleted-into-gap"),
			})
			if err != nil {
				t.Fatalf("append event to prune: %v", err)
			}
			cut := pruned.Sequence
			//nolint:staticcheck // Exercise restore compatibility with pre-B-3375cb42 physical gaps.
			if err := srcLog.PruneTenantThroughCheckpoint(ctx, tenantB, cut, nil); err != nil {
				t.Fatalf("prune event into exact-history gap: %v", err)
			}

			var stream bytes.Buffer
			if _, err := backup.WriteLogThrough(ctx, srcLog, &stream, cut); err != nil {
				t.Fatalf("WriteLogThrough: %v", err)
			}
			restoredLog := openLog(t)
			if _, err := backup.RestoreLog(ctx, restoredLog, bytes.NewReader(stream.Bytes())); err != nil {
				t.Fatalf("RestoreLog: %v", err)
			}

			dst := newStore(t)
			p := projections.New(dst)
			if err := p.Rebuild(ctx, restoredLog); err != nil {
				t.Fatalf("Rebuild exact restored history: %v", err)
			}
			checkpoint, err := dst.ProjectionCheckpoint(ctx)
			if err != nil {
				t.Fatalf("ProjectionCheckpoint: %v", err)
			}
			if checkpoint != cut {
				t.Fatalf("checkpoint after rebuild = %d, want exact restored cut %d", checkpoint, cut)
			}

			next, err := restoredLog.Append(ctx, events.Event{
				Type: projections.EventTenantRegistered, TenantID: tenantB,
				Data: tenantRegistered("after-restored-gap"),
			})
			if err != nil {
				t.Fatalf("append after restored gap: %v", err)
			}
			if next.Sequence != cut+1 {
				t.Fatalf("next sequence = %d, want %d", next.Sequence, cut+1)
			}
			if err := p.ProjectCatchUp(ctx, restoredLog); err != nil {
				t.Fatalf("catch up event after restored gap: %v", err)
			}
			tenants, err := dst.ListTenants(ctx)
			if err != nil {
				t.Fatalf("ListTenants: %v", err)
			}
			if len(tenants) != tc.wantTenants {
				t.Fatalf("tenants after catch-up = %d, want %d", len(tenants), tc.wantTenants)
			}
			if err := p.ProjectCatchUp(ctx, restoredLog); err != nil {
				t.Fatalf("second catch up: %v", err)
			}
			tenants, err = dst.ListTenants(ctx)
			if err != nil {
				t.Fatalf("ListTenants after second catch-up: %v", err)
			}
			if len(tenants) != tc.wantTenants {
				t.Fatalf("second catch-up reapplied next event: tenants = %d, want %d", len(tenants), tc.wantTenants)
			}
		})
	}
}

func TestFullDRConcurrentMutationRestoresSingleEventCut(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL + NATS")
	}
	ctx := context.Background()
	src := newStore(t)
	srcLog := openLog(t)
	resetFullDRState(t, src)

	orch := orchestrator.NewOrchestrator(srcLog, src, orchestrator.NewOutbox(src))
	if _, err := orch.CreateOwner(ctx, tenantA, "workload", "baseline-before-cut", ""); err != nil {
		t.Fatalf("CreateOwner baseline: %v", err)
	}

	mutationAppended := make(chan struct{})
	allowMutationCommit := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- appendEventAndOutboxBeforeCommit(ctx, src, srcLog, mutationAppended, allowMutationCommit)
	}()
	select {
	case <-mutationAppended:
	case err := <-mutationDone:
		t.Fatalf("concurrent mutation ended before backup cut: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent mutation did not append before backup cut")
	}

	var (
		tx  pgx.Tx
		cut uint64
	)
	backupCutDone := make(chan error, 1)
	go func() {
		backupCutDone <- src.WithBackupWriteFence(ctx, func(ctx context.Context) error {
			var err error
			cut, err = srcLog.LastSequence(ctx)
			if err != nil {
				return fmt.Errorf("capture event cut: %w", err)
			}
			tx, err = backup.BeginPostgresStateSnapshot(ctx, src)
			if err != nil {
				return fmt.Errorf("begin backup snapshot: %w", err)
			}
			return nil
		})
	}()

	select {
	case err := <-backupCutDone:
		t.Fatalf("backup cut completed before the in-flight write committed (err=%v)", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(allowMutationCommit)
	if err := <-mutationDone; err != nil {
		t.Fatalf("concurrent mutation: %v", err)
	}
	if err := <-backupCutDone; err != nil {
		t.Fatalf("capture fenced backup cut: %v", err)
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := orch.CreateOwner(ctx, tenantA, "workload", "excluded-after-cut", ""); err != nil {
		t.Fatalf("CreateOwner excluded-after-cut: %v", err)
	}
	if err := insertOutboxRow(ctx, src, "excluded-after-cut"); err != nil {
		t.Fatalf("insert post-cut outbox row: %v", err)
	}

	var eventsBuf bytes.Buffer
	written, err := backup.WriteLogThrough(ctx, srcLog, &eventsBuf, cut)
	if err != nil {
		t.Fatalf("WriteLogThrough: %v", err)
	}
	if uint64(written) != cut { // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		t.Fatalf("event backup wrote %d events, want cut sequence %d", written, cut)
	}
	var pgBuf bytes.Buffer
	exportSummary, err := backup.WritePostgresStateTx(ctx, tx, &pgBuf, cut)
	if err != nil {
		t.Fatalf("WritePostgresStateTx: %v", err)
	}
	if exportSummary.EventCutSequence != cut {
		t.Fatalf("postgres-state event cut = %d, want %d", exportSummary.EventCutSequence, cut)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("release backup snapshot: %v", err)
	}
	tx = nil

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
	if restoreSummary.EventCutSequence != cut {
		t.Fatalf("restored postgres-state event cut = %d, want %d", restoreSummary.EventCutSequence, cut)
	}

	got := ownerNames(t, dst, tenantA)
	if !containsString(got, "baseline-before-cut") || !containsString(got, "included-before-cut") {
		t.Fatalf("owners after cut restore = %v, want baseline and included-before-cut", got)
	}
	if containsString(got, "excluded-after-cut") {
		t.Fatalf("owners after cut restore = %v, contains mutation after backup cut", got)
	}
	if got := outboxRowsByIdempotencyKey(t, dst, "full-dr-concurrent-outbox"); got != 1 {
		t.Fatalf("outbox rows restored for pre-cut mutation = %d, want 1", got)
	}
	if got := outboxRowsByIdempotencyKey(t, dst, "excluded-after-cut"); got != 0 {
		t.Fatalf("outbox rows restored for post-cut mutation = %d, want 0", got)
	}
}

func appendEventAndOutboxBeforeCommit(ctx context.Context, st *store.Store, log *events.Log, appended chan<- struct{}, allowCommit <-chan struct{}) error {
	return st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		payload, err := fullDROwnerCreatedPayload("00000000-0000-0000-0000-00000000d001", "included-before-cut")
		if err != nil {
			return err
		}
		ev, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: payload})
		if err != nil {
			return err
		}
		if err := projections.New(st).ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if err := insertOutboxRowTx(ctx, tx, "full-dr-concurrent-outbox"); err != nil {
			return err
		}
		close(appended)
		<-allowCommit
		return nil
	})
}

func insertOutboxRow(ctx context.Context, st *store.Store, key string) error {
	return st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return insertOutboxRowTx(ctx, tx, key)
	})
}

func insertOutboxRowTx(ctx context.Context, tx pgx.Tx, key string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, attempts, next_attempt_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		tenantA, "webhook", []byte(`{"event":"concurrent"}`), key, "pending", 0, time.Now().UTC())
	return err
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
	approvalResource := "identity:00000000-0000-0000-0000-00000000aa01"
	err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		statements := []struct {
			sql  string
			args []any
		}{
			// L4: silo placement and residency. An operator's placement decision,
			// never derived from the event log — a restore that lost it would
			// silently revert this tenant to the shared isolation default.
			{`INSERT INTO tenant_silos (tenant_id, slug, isolation_model, residency_zone, status) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, "tenant-a", "silo", "eu-west", "active"}},
			// L2: provider billing meters. Not a log projection — usage is
			// counted from live activity and can never be replayed — so a
			// restore that lost them means the provider cannot invoice for the
			// period, and the coverage row is exactly what would have told them
			// the figure was short.
			{`INSERT INTO provider_usage_meters (tenant_id, meter, period_start, kind, value) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, "certificates.issued", now.Truncate(time.Hour), "counter", int64(17)}},
			{`INSERT INTO provider_usage_coverage (tenant_id, observed_from, observed_to) VALUES ($1, $2, $3)`, []any{tenantA, now.Add(-time.Hour), now}},
			{`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, scopes, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`, []any{"00000000-0000-0000-0000-00000000a001", tenantA, "full-dr-api-token-hash", "ci", []string{"owners:read"}, now.Add(time.Hour)}},
			{`INSERT INTO agent_bootstrap_tokens (id, tenant_id, token_hash, allowed_identity, expires_at) VALUES ($1, $2, $3, $4, $5)`, []any{"00000000-0000-0000-0000-00000000a002", tenantA, "full-dr-bootstrap-hash", "edge-1", now.Add(time.Hour)}},
			// A3: the credential-redemption ledger must survive a restore intact.
			// It is the single-use gate, and nothing in the event log can rebuild
			// it — a restore that lost it would make every in-flight attempt
			// redeemable a second time.
			{`INSERT INTO agent_job_credential_redemptions (tenant_id, job_id, attempt, agent_id, binding, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`, []any{tenantA, int64(4242), 1, "00000000-0000-0000-0000-00000000a003", []byte("full-dr-redemption-binding"), now.Add(time.Hour)}},
			// D4/A1: the signed receipt ledger. It is not a log projection — no
			// projector rebuilds it — so a restore that lost it would lose the
			// record of what agents reported and what was refused.
			{`INSERT INTO agent_job_receipts (tenant_id, job_id, attempt, agent, kind, outcome, state, reason, signer_fingerprint, statement, signature, observed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, []any{tenantA, int64(4242), 1, "edge-relay-1", "connector.deploy", "executed", "verified", "", "full-dr-signer-fp", "full-dr-statement", "ZnVsbC1kci1zaWduYXR1cmU=", now}},
			// C3: declared segments. Operator declarations that no replay
			// rebuilds — a restore that lost them would silently discard real
			// operator work and make an estate look unmeasured.
			{`INSERT INTO discovery_segments (tenant_id, id, name, ranges, staleness_hours, excluded, exclusion_reason, last_swept_at, last_swept_by, last_found_count) VALUES ($1, $2, $3, $4::text[], $5, $6, $7, $8, $9, $10)`, []any{tenantA, "00000000-0000-0000-0000-00000000a00d", "full-dr-dmz", []string{"10.0.1.0/24"}, 24, false, "", now, "full-dr-relay", 7}},
			{`INSERT INTO attestations (id, tenant_id, kind, evidence, verified_at) VALUES ($1, $2, $3, $4::jsonb, $5)`, []any{"00000000-0000-0000-0000-00000000a003", tenantA, "oidc", `{"issuer":"ci"}`, now}},
			{`INSERT INTO audit_checkpoints (tenant_id, boundary_seq, boundary_hash, record_count, archive_uri) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, int64(10), "full-dr-boundary", int64(3), "s3://archive/full-dr"}},
			{`INSERT INTO ca_authorities (id, tenant_id, common_name, kind, status, certificate_pem, serial, not_after, max_path_len, permitted_dns_names, ekus) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, []any{caID, tenantA, "Full DR Root", "root", "active", "-----BEGIN CERTIFICATE-----\nFULLDR\n-----END CERTIFICATE-----", "ca-01", now.Add(365 * 24 * time.Hour), 1, []string{"example.com"}, []string{"serverAuth"}}},
			{`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed) VALUES ($1, $2, $3, $4, $5, $6)`, []any{"00000000-0000-0000-0000-00000000a005", tenantA, "connector", "target-1", "password", []byte{0xaa, 0xbb}}},
			{`INSERT INTO crypto_assets (id, tenant_id, signature, kind, location, algorithm, key_bits, strength, quantum_vulnerable, out_of_policy, reasons) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, []any{"00000000-0000-0000-0000-00000000a006", tenantA, "tls:edge:ecdsa", "tls", "edge", "ECDSA-P256", 256, "strong", false, false, []string{"baseline"}}},
			{`INSERT INTO ct_log_checkpoints (tenant_id, log_url, next_index, updated_at) VALUES ($1, $2, $3, $4)`, []any{tenantA, "https://ct.example/log", int64(42), now}},
			{`INSERT INTO ct_watched_domains (id, tenant_id, domain) VALUES ($1, $2, $3)`, []any{"00000000-0000-0000-0000-00000000a007", tenantA, "example.com"}},
			{`INSERT INTO deployment_target_revisions (tenant_id, target_id, revision_id, name, type, config, enabled, created_at) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`, []any{tenantA, "00000000-0000-0000-0000-00000000a008", "full-dr-revision-1", "edge", "kubernetes", `{"namespace":"prod"}`, true, now}},
			{`INSERT INTO deployment_targets (id, tenant_id, name, type, config, revision_id) VALUES ($1, $2, $3, $4, $5::jsonb, $6)`, []any{"00000000-0000-0000-0000-00000000a008", tenantA, "edge", "kubernetes", `{"namespace":"prod"}`, "full-dr-revision-1"}},
			{`INSERT INTO idempotency_keys (tenant_id, key, status, result, completed_at) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, "full-dr-idempotency", "completed", []byte(`{"ok":true}`), now}},
			{`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester, required) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, approvalResource, "issue", "requester", 2}},
			{`INSERT INTO issuance_approvals (tenant_id, resource, action, approver, approved_at) VALUES ($1, $2, $3, $4, $5)`, []any{tenantA, approvalResource, "issue", "approver-1", now}},
			{`INSERT INTO notification_routing_policies (id, tenant_id, name, channels_by_severity, default_channels, created_at, updated_at) VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7)`, []any{"00000000-0000-0000-0000-00000000a012", tenantA, "expiry-default", `{"critical":["pagerduty","slack"],"low":["email"]}`, `["email"]`, now, now}},
			{`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, status, attempts, next_attempt_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`, []any{tenantA, "webhook", []byte(`{"event":"full-dr"}`), "full-dr-outbox", "pending", 0, now}},
			{`INSERT INTO policy_bindings (id, tenant_id, name, policy, scope) VALUES ($1, $2, $3, $4, $5::jsonb)`, []any{"00000000-0000-0000-0000-00000000a009", tenantA, "default", "allow", `{"project":"prod"}`}},
			{`INSERT INTO privacy_subject_erasure_operations
			        (tenant_id, operation_id, request_binding, event_id, event_sequence,
			         subject_ref, requested_by_ref, reason, selectors, counts, erased_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11)`,
				[]any{
					tenantA, "full-dr-privacy-operation", "sha256:full-dr-request",
					"full-dr-privacy-event", int64(17), "subject:full-dr",
					"actor:full-dr", "approved erasure", `{}`, `{"owners":1}`, now,
				}},
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

func outboxRowsByIdempotencyKey(t *testing.T, st *store.Store, key string) int {
	t.Helper()
	var n int
	if err := st.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, key).Scan(&n); err != nil {
		t.Fatalf("count outbox rows for %s: %v", key, err)
	}
	return n
}

func fullDROwnerCreatedPayload(id, name string) ([]byte, error) {
	return json.Marshal(projections.OwnerCreated{ID: id, Kind: "workload", Name: name})
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
