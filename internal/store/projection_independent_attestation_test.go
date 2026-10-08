// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A read-model TRUNCATE CASCADE reaches attestations through its identity FK.
// Independent attestation evidence must survive a rebuild even when no event
// can recreate it; this is also the final step of a full backup restore.
func TestReadModelRebuildPreservesIndependentAttestation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	ctx := context.Background()
	st := newStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "rebuild attestation"}); err != nil {
		t.Fatal(err)
	}
	verified := time.Now().UTC().Truncate(time.Microsecond)
	want := store.Attestation{
		ID: "b78c638d-5d48-4d11-987e-29baead13510", TenantID: tenantA,
		Kind: "operator-evidence", Evidence: json.RawMessage(`{"source":"independent"}`),
		VerifiedAt: &verified,
	}
	if err := st.UpsertAttestation(ctx, want); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildReadModelTx(ctx, func(tx pgx.Tx) error {
		return st.UpsertTenantTx(ctx, tx, store.Tenant{TenantID: tenantA, Name: "rebuild attestation"})
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAttestation(ctx, tenantA, want.ID)
	if err != nil {
		t.Fatalf("independent attestation was erased by read-model rebuild: %v", err)
	}
	var gotEvidence, wantEvidence any
	if err := json.Unmarshal(got.Evidence, &gotEvidence); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want.Evidence, &wantEvidence); err != nil {
		t.Fatal(err)
	}
	if got.Kind != want.Kind || !reflect.DeepEqual(gotEvidence, wantEvidence) ||
		got.VerifiedAt == nil || !got.VerifiedAt.Equal(verified) {
		t.Fatalf("restored attestation differs from independent source: %+v", got)
	}
}

func TestSnapshotRestorePreservesIndependentAttestation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	ctx := context.Background()
	st := newStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "snapshot attestation"}); err != nil {
		t.Fatal(err)
	}
	att := store.Attestation{
		ID: "21a8aed2-914e-44bf-a9d0-e068dd3e24a3", TenantID: tenantA,
		Kind: "operator-evidence", Evidence: json.RawMessage(`{"source":"outside-snapshot"}`),
	}
	if err := st.UpsertAttestation(ctx, att); err != nil {
		t.Fatal(err)
	}
	if count, err := st.WriteReadModelSnapshots(ctx); err != nil || count != 1 {
		t.Fatalf("capture snapshot: count=%d error=%v", count, err)
	}
	if err := st.RestoreReadModelTx(ctx, func(tx pgx.Tx) error {
		_, err := st.RestoreSnapshotsTx(ctx, tx)
		return err
	}); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}
	got, err := st.GetAttestation(ctx, tenantA, att.ID)
	var gotEvidence, wantEvidence any
	if err == nil {
		err = json.Unmarshal(got.Evidence, &gotEvidence)
	}
	if err == nil {
		err = json.Unmarshal(att.Evidence, &wantEvidence)
	}
	if err != nil || got.Kind != att.Kind || !reflect.DeepEqual(gotEvidence, wantEvidence) {
		t.Fatalf("independent attestation lost across snapshot restore: got=%+v error=%v", got, err)
	}
}

// The signed attestation and alert intent commit together. Once a delivered
// alert is reclaimed, replaying that already-committed attestation must not
// resurrect a pending notification during a rebuild or full restore.
func TestReadModelRebuildDoesNotRequeuePreservedRestoreDrillAlert(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	ctx := context.Background()
	st := newStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "drill alert"}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	att := store.Attestation{
		ID: "a10ff342-207f-40f1-89dc-556776b54e25", TenantID: tenantA,
		Kind: "backup.restore_drill", Evidence: json.RawMessage(`{"outcome":"failed"}`),
		VerifiedAt: &at, CreatedAt: at,
	}
	const alertKey = "restore-drill-alert:a10ff342-207f-40f1-89dc-556776b54e25"
	alert := []byte(`{"kind":"backup.restore_drill_failed"}`)
	apply := func(tx pgx.Tx) error {
		return st.ApplyRestoreDrillAttestationTx(ctx, tx, att, "notification.restore_drill", alert, alertKey)
	}
	if err := st.WithTenant(ctx, tenantA, apply); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, alertKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildReadModelTx(ctx, func(tx pgx.Tx) error {
		if err := st.UpsertTenantTx(ctx, tx, store.Tenant{TenantID: tenantA, Name: "drill alert"}); err != nil {
			return err
		}
		return apply(tx)
	}); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantA, alertKey).Scan(&pending)
	}); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("rebuild resurrected %d already completed restore-drill alert(s)", pending)
	}
	if _, err := st.GetAttestation(ctx, tenantA, att.ID); err != nil {
		t.Fatalf("signed attestation was not retained: %v", err)
	}
}
