// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestRestoreDrillRunPersistsSignedTenantHistoryAndSurvivesColdRebuild(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats"),
	}, st, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	projector := projections.New(st, projections.WithRestoreDrillVerificationKeys(key.JWKS()))
	registered, err := log.Append(ctx, events.Event{
		ID: "restore-drill-served-tenant", Type: projections.EventTenantRegistered,
		TenantID: servedTestTenant, Time: time.Unix(100, 0).UTC(),
		Data: []byte(`{"name":"restore drill tenant"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	want := backup.DrillAttestation{
		Outcome: backup.DrillFailed, StartedAt: time.Unix(200, 0).UTC(),
		CompletedAt: time.Unix(230, 0).UTC(), RPOSeconds: 90_000,
		RTOSeconds: 30, Detail: "closed restore failure",
	}
	srv := &Server{
		store: st, log: log, proj: projector, restoreDrillSigner: key,
		restoreDrillRPO: 24 * time.Hour, restoreDrillRTO: time.Hour,
		restoreDrill: func(context.Context) (backup.DrillAttestation, error) { return want, nil },
	}
	if _, err := srv.RunRestoreDrillOnce(ctx); err != nil {
		t.Fatalf("RunRestoreDrillOnce: %v", err)
	}
	assertDurableRestoreDrill(t, ctx, st, key, want)
	assertServedRestoreDrillHistory(t, st, key, http.StatusOK)
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE attestations
		    SET evidence = jsonb_set(evidence, '{attestation,detail}', '"tampered"'::jsonb)
		  WHERE tenant_id = $1 AND kind = $2`, servedTestTenant, projections.RestoreDrillAttestationKind); err != nil {
		t.Fatal(err)
	}
	assertServedRestoreDrillHistory(t, st, key, http.StatusInternalServerError)

	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild: %v", err)
	}
	assertDurableRestoreDrill(t, ctx, st, key, want)
	assertServedRestoreDrillHistory(t, st, key, http.StatusOK)
}

func assertServedRestoreDrillHistory(t *testing.T, st *store.Store, key *jose.SigningKey, wantStatus int) {
	t.Helper()
	handler := api.New(st, nil, nil, api.WithInsecureHeaderResolver(), api.WithRestoreDrillSigningKey(key))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/dr-posture", nil)
	req.Header.Set("X-Tenant-ID", servedTestTenant)
	req.Header.Set("X-Subject", "dr-reader")
	req.Header.Set("X-Roles", "viewer")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("GET DR posture status=%d want=%d body=%s", rec.Code, wantStatus, rec.Body.String())
	}
	if wantStatus != http.StatusOK {
		return
	}
	var posture api.DRPosture
	if err := json.NewDecoder(rec.Body).Decode(&posture); err != nil {
		t.Fatal(err)
	}
	if len(posture.DrillHistory) != 1 || posture.LastDrill == nil ||
		!posture.DrillHistory[0].SignatureVerified || len(posture.DrillHistory[0].SignedEvidence) == 0 {
		t.Fatalf("served restore-drill history = %+v", posture)
	}
}

func assertDurableRestoreDrill(t *testing.T, ctx context.Context, st *store.Store, key *jose.SigningKey, want backup.DrillAttestation) {
	t.Helper()
	rows, err := st.ListAttestationsByKind(ctx, servedTestTenant, projections.RestoreDrillAttestationKind, 50)
	if err != nil || len(rows) != 1 {
		t.Fatalf("restore-drill rows=%d err=%v", len(rows), err)
	}
	var evidence backup.SignedDrillEvidence
	if err := json.Unmarshal(rows[0].Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Attestation.Outcome != want.Outcome || evidence.Attestation.Detail != want.Detail {
		t.Fatalf("stored attestation = %+v", evidence.Attestation)
	}
	if err := backup.VerifyDrillEvidence(evidence, key.JWKS()); err != nil {
		t.Fatalf("offline verification: %v", err)
	}
	var alerts int
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		servedTestTenant, notify.DestinationRestoreDrill).Scan(&alerts); err != nil || alerts != 1 {
		t.Fatalf("restore-drill alerts=%d err=%v", alerts, err)
	}
}
