// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Uses the actual configured source, shipped child signer and projector capture.
// The opt-in request is explicit fixture input; this is not public operator proof.
func TestEventProtectionSnapshotCaptureProtectsTenantPayload(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour)
	cfg := info.Config
	st, err := store.Open(t.Context(), cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	signer, key, err := openAuditSigningRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runtime.Close(); _ = log.Close() }()
	captured, err := projections.New(st, runtime.projectionOptions()...).Snapshot(t.Context())
	if err != nil || captured != 2 {
		t.Fatalf("actual snapshot capture failed: %d %v", captured, err)
	}
	read := func(tenant string) []byte {
		t.Helper()
		var payload []byte
		if err := st.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(), `SELECT payload::text FROM read_model_snapshots WHERE tenant_id=$1`, tenant).Scan(&payload)
		}); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	raw := read(info.Tenant)
	if bytes.Contains(raw, []byte("protected-artifact@example.invalid")) || bytes.Contains(raw, []byte("Protected owner")) {
		t.Error("configured snapshot retained opted-in tenant's private owner in plaintext")
	}
	if !bytes.Contains(read(info.Neighbor), []byte("Legacy SQL neighbor")) {
		t.Error("never-enabled neighbor snapshot changed unexpectedly")
	}
	cut, err := st.ProjectionCheckpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// This direct real-storage restore has no source-rebuild fallback: it proves
	// the actual encrypted SQL cache opens, validates and imports its tenant rows.
	provider := eventprivacy.SourceSnapshotProtection{Policy: runtime.policy, Custody: runtime.custody}
	if err := st.WithPrivacyReadModelReplacementBarrier(t.Context(), func(barrier context.Context) error {
		return st.WithProjectionLock(barrier, func(locked context.Context) error {
			return log.WithHistoryRead(locked, func(read context.Context) error {
				return st.RestoreReadModelTx(read, func(tx pgx.Tx) error {
					count, err := st.RestoreSnapshotsTx(read, tx, provider)
					if err != nil {
						return err
					}
					if count != 2 {
						t.Errorf("active cache imported %d tenants, want 2", count)
					}
					return st.SetProjectionCheckpointTx(read, tx, cut)
				})
			})
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RestoreReadModelTx(t.Context(), func(tx pgx.Tx) error { return st.ResetProjectionCheckpointTx(t.Context(), tx) }); err != nil {
		t.Fatal(err)
	}
	handled, err := projections.New(st, runtime.projectionOptions()...).RestoreFromSnapshot(t.Context(), log)
	if err != nil || !handled {
		t.Fatalf("actual active snapshot boot failed: %t %v", handled, err)
	}
	var owners int
	if err := st.WithTenant(t.Context(), info.Tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM owners WHERE tenant_id=$1 AND email=$2`, info.Tenant, "protected-artifact@example.invalid").Scan(&owners)
	}); err != nil || owners != 1 {
		t.Fatalf("active encrypted cache did not restore owner: %d %v", owners, err)
	}
	missing := &eventprivacy.ErasurePlanner{Policy: runtime.policy}
	if _, err := projections.New(st, projections.WithEventProtectionErasurePlanner(missing)).Snapshot(t.Context()); err == nil {
		t.Fatal("retained activation without a configured custody adapter produced a plaintext snapshot")
	}
}

type eventProtectionSnapshotRow struct {
	Tenant    string
	Covered   int64
	Version   int
	Payload   []byte
	CreatedAt time.Time
}

func TestEventProtectionSnapshotRestoreHonorsCurrentDestruction(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Nanosecond)
	cfg := info.Config
	st, err := store.Open(t.Context(), cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	signer, key, err := openAuditSigningRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runtime.Close(); _ = log.Close() }()
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: runtime})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	neighbor, err := srv.orch.CreateOwner(t.Context(), info.Neighbor, "team", "Snapshot neighbor", "snapshot-neighbor@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st, runtime.projectionOptions()...)
	if count, err := projector.Snapshot(t.Context()); err != nil || count != 2 {
		t.Fatalf("capture old snapshot: %d %v", count, err)
	}
	var frames []eventProtectionSnapshotRow
	var digests []string
	for _, tenant := range []string{info.Tenant, info.Neighbor} {
		row := eventProtectionSnapshotRow{Tenant: tenant}
		if err := st.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(), `SELECT covered_seq,format_version,payload,created_at FROM read_model_snapshots WHERE tenant_id=$1`, tenant).Scan(&row.Covered, &row.Version, &row.Payload, &row.CreatedAt)
		}); err != nil {
			t.Fatal(err)
		}
		row.Payload = bytes.Clone(row.Payload)
		frames = append(frames, row)
		digests = append(digests, crypto.SHA256Hex(row.Payload))
	}
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: info.Tenant, RegistrationIdentity: info.Registration}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Run("before-old-cache-import", func(t *testing.T) { eventKeyAssertNoTenantSQLResidue(t, st, info.Tenant) })
	ref := eventprotect.KeyRef{TenantID: info.Tenant, ID: info.KeyID}
	state, found, err := runtime.custody.LookupKeyState(t.Context(), ref)
	if err != nil || !found || state.Phase != eventprotect.CustodyKeyDestroyed || state.Receipt == "" {
		t.Fatalf("original independent material not removed: %v", err)
	}
	// Import the exact old cache generation as an isolated old-PG recovery fixture.
	// These cache rows have no FK to live registration; nothing is served mid-restore.
	for _, row := range frames {
		if err := st.WithTenant(t.Context(), row.Tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `INSERT INTO read_model_snapshots (tenant_id,covered_seq,format_version,payload,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id) DO UPDATE SET covered_seq=EXCLUDED.covered_seq,format_version=EXCLUDED.format_version,payload=EXCLUDED.payload,created_at=EXCLUDED.created_at`, row.Tenant, row.Covered, row.Version, row.Payload, row.CreatedAt)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RestoreReadModelTx(t.Context(), func(tx pgx.Tx) error { return st.ResetProjectionCheckpointTx(t.Context(), tx) }); err != nil {
		t.Fatal(err)
	}
	handled, err := projector.RestoreFromSnapshot(t.Context(), log)
	if err != nil || !handled {
		t.Fatalf("current-erasure snapshot recovery failed: %t %v", handled, err)
	}
	t.Run("after-current-source-rebuild", func(t *testing.T) { eventKeyAssertNoTenantSQLResidue(t, st, info.Tenant) })
	if got, err := st.GetOwner(t.Context(), info.Neighbor, neighbor.ID); err != nil || got.Email != "snapshot-neighbor@example.invalid" {
		t.Fatalf("snapshot recovery lost neighbor: %v", err)
	}
	after, found, err := runtime.custody.LookupKeyState(t.Context(), ref)
	if err != nil || !found || after.Phase != state.Phase || after.Receipt != state.Receipt || after.Creation.Digest() != state.Creation.Digest() {
		t.Fatal("snapshot restore altered original destruction evidence")
	}
	for index, row := range frames {
		if crypto.SHA256Hex(row.Payload) != digests[index] {
			t.Fatal("restore rewrote retained old cache artifact")
		}
	}
}
