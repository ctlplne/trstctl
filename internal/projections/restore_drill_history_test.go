// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestRestoreDrillEvidenceProjectsDurableHistoryAndAlert(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st, projections.WithRestoreDrillVerificationKeys(key.JWKS()))
	registered := appendEvent(t, ctx, log, events.Event{
		ID: "restore-drill-tenant", Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: time.Unix(100, 0).UTC(), Data: []byte(`{"name":"drill tenant"}`),
	})
	if err := projector.Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	evidence, err := backup.SignDrillEvidence(ctx, key, "drill-global-1", backup.DrillAttestation{
		Outcome: backup.DrillFailed, StartedAt: time.Unix(200, 0).UTC(),
		CompletedAt: time.Unix(230, 0).UTC(), RPOSeconds: 7_300,
		RTOSeconds: 30, Detail: "restore failed closed",
	}, 2*time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	payload := projections.RestoreDrillRecorded{
		AttestationID: projections.RestoreDrillAttestationID(tenantA, evidence.DrillID),
		Evidence:      evidence,
	}
	recorded := appendEvent(t, ctx, log, events.Event{
		ID: "restore-drill-recorded", Type: projections.EventRestoreDrillRecorded,
		TenantID: tenantA, Time: evidence.Attestation.CompletedAt, Data: mustMarshal(t, payload),
	})
	if err := projector.Apply(ctx, recorded); err != nil {
		t.Fatalf("project restore drill: %v", err)
	}
	assertRestoreDrillProjection(t, ctx, st, evidence)

	// A cold rebuild must reproduce both the immutable history and the exact
	// idempotent notification intent from the event source of truth.
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild restore-drill history: %v", err)
	}
	assertRestoreDrillProjection(t, ctx, st, evidence)
}

func TestRestoreDrillProjectionRejectsTamperedEvidenceWithoutStateOrAlert(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := backup.SignDrillEvidence(ctx, key, "drill-global-2", backup.DrillAttestation{
		Outcome: backup.DrillFailed, StartedAt: time.Unix(300, 0).UTC(),
		CompletedAt: time.Unix(330, 0).UTC(), Detail: "original",
	}, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	original := evidence
	evidence.Attestation.Detail = "tampered"
	payload := projections.RestoreDrillRecorded{
		AttestationID: projections.RestoreDrillAttestationID(tenantA, evidence.DrillID),
		Evidence:      evidence,
	}
	err = projections.New(st, projections.WithRestoreDrillVerificationKeys(key.JWKS())).Apply(ctx, events.Event{
		ID: "restore-drill-tampered", Type: projections.EventRestoreDrillRecorded,
		TenantID: tenantA, Time: evidence.Attestation.CompletedAt, Sequence: 1,
		SchemaVersion: 1, Data: mustMarshal(t, payload),
	})
	if err == nil {
		t.Fatal("projector accepted tampered restore-drill evidence")
	}
	rebound := projections.RestoreDrillRecorded{
		AttestationID: "54000000-0000-4000-8000-000000000002",
		Evidence:      original,
	}
	err = projections.New(st, projections.WithRestoreDrillVerificationKeys(key.JWKS())).Apply(ctx, events.Event{
		ID: "restore-drill-rebound", Type: projections.EventRestoreDrillRecorded,
		TenantID: tenantA, Time: original.Attestation.CompletedAt, Sequence: 2,
		SchemaVersion: 1, Data: mustMarshal(t, rebound),
	})
	if err == nil {
		t.Fatal("projector accepted a signed restore drill rebound to an arbitrary history id")
	}
	rows, listErr := st.ListAttestationsByKind(ctx, tenantA, projections.RestoreDrillAttestationKind, 50)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(rows) != 0 {
		t.Fatalf("tampered evidence created %d history rows", len(rows))
	}
	var alerts int
	if scanErr := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		tenantA, notify.DestinationRestoreDrill).Scan(&alerts); scanErr != nil || alerts != 0 {
		t.Fatalf("tampered evidence alerts = %d, err=%v", alerts, scanErr)
	}
}

func TestRestoreDrillHistoryIsNewestFirst(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st, projections.WithRestoreDrillVerificationKeys(key.JWKS()))
	for i, completed := range []time.Time{time.Unix(410, 0).UTC(), time.Unix(510, 0).UTC()} {
		drillID := fmt.Sprintf("ordered-drill-%d", i+1)
		evidence, signErr := backup.SignDrillEvidence(ctx, key, drillID, backup.DrillAttestation{
			Outcome: backup.DrillRestored, StartedAt: completed.Add(-10 * time.Second),
			CompletedAt: completed, RPOSeconds: 60, RTOSeconds: 10,
		}, 24*time.Hour, time.Hour)
		if signErr != nil {
			t.Fatal(signErr)
		}
		payload := projections.RestoreDrillRecorded{
			AttestationID: projections.RestoreDrillAttestationID(tenantA, evidence.DrillID),
			Evidence:      evidence,
		}
		if err := projector.Apply(ctx, events.Event{
			ID: fmt.Sprintf("ordered-event-%d", i+1), Type: projections.EventRestoreDrillRecorded,
			TenantID: tenantA, Time: completed, Sequence: uint64(i + 1),
			SchemaVersion: 1, Data: mustMarshal(t, payload),
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := st.ListAttestationsByKind(ctx, tenantA, projections.RestoreDrillAttestationKind, 50)
	if err != nil || len(rows) != 2 {
		t.Fatalf("ordered restore-drill rows=%d err=%v", len(rows), err)
	}
	for i, want := range []string{"ordered-drill-2", "ordered-drill-1"} {
		var evidence backup.SignedDrillEvidence
		if err := json.Unmarshal(rows[i].Evidence, &evidence); err != nil {
			t.Fatal(err)
		}
		if evidence.DrillID != want {
			t.Fatalf("history[%d] drill=%q want newest-first %q", i, evidence.DrillID, want)
		}
	}
	otherTenantRows, err := st.ListAttestationsByKind(ctx, tenantB, projections.RestoreDrillAttestationKind, 50)
	if err != nil || len(otherTenantRows) != 0 {
		t.Fatalf("tenant B read tenant A restore-drill history: rows=%d err=%v", len(otherTenantRows), err)
	}
}

func appendEvent(t *testing.T, ctx context.Context, log *events.Log, event events.Event) events.Event {
	t.Helper()
	appended, err := log.Append(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	return appended
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertRestoreDrillProjection(t *testing.T, ctx context.Context, st *store.Store, want backup.SignedDrillEvidence) {
	t.Helper()
	rows, err := st.ListAttestationsByKind(ctx, tenantA, projections.RestoreDrillAttestationKind, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("restore-drill history rows = %d, want 1", len(rows))
	}
	var got backup.SignedDrillEvidence
	if err := json.Unmarshal(rows[0].Evidence, &got); err != nil {
		t.Fatal(err)
	}
	if got.DrillID != want.DrillID || got.Signature != want.Signature {
		t.Fatalf("projected evidence = %+v, want drill/signature from %+v", got, want)
	}
	var destination, idem string
	var alertJSON []byte
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT destination, idempotency_key, payload FROM outbox
		  WHERE tenant_id = $1 AND destination = $2`, tenantA, notify.DestinationRestoreDrill).
		Scan(&destination, &idem, &alertJSON); err != nil {
		t.Fatal(err)
	}
	var alert notify.Alert
	if err := json.Unmarshal(alertJSON, &alert); err != nil {
		t.Fatal(err)
	}
	if destination != notify.DestinationRestoreDrill || idem == "" ||
		alert.Kind != notify.KindRestoreDrillFailed || alert.TenantID != tenantA ||
		alert.OperationID == "" || alert.Severity != notify.AlertSeverityCritical {
		t.Fatalf("restore-drill alert = %+v destination=%q idem=%q", alert, destination, idem)
	}
}
