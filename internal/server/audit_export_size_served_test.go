// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/store"
)

// This regression uses real PostgreSQL, NATS and the real bounded signer RPC.
// The helper's signer runs in the test process; separate-process custody remains
// covered by TestAuditEvidenceOverRealSignerBinary and the live CLM deployment.
func TestServedLargeAuditExportOffersRecordStreamWithoutRaisingSignerLimit(t *testing.T) {
	ctx := t.Context()
	const tenantID = "11111111-1111-4111-8111-111111111132"
	cfg := config.Default()
	configureExternalAuditTestSigner(t, cfg)
	runtime, key, err := openAuditSigningRuntime(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "bounded export"}); err != nil {
		t.Fatal(err)
	}
	token := seedServedAPIToken(t, ctx, st, tenantID, "bounded-export", []string{string(authz.AuditRead)})
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for n := 0; n < 17; n++ {
		note := "small public control"
		if n > 0 {
			note = strings.Repeat("x", 54<<10)
		}
		data, err := json.Marshal(map[string]any{"ordinal": n, "note": note})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{TenantID: tenantID, Type: "audit.export.size-control", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?limit=10000", token, "", nil)
	if code != http.StatusRequestEntityTooLarge || !bytes.Contains(body, []byte("NDJSON")) {
		t.Fatalf("large JWS export = %d %s; want actionable 413 with NDJSON recovery", code, body)
	}
	if bytes.Contains(body, []byte("grpc")) {
		t.Fatalf("transport internals leaked: %s", body)
	}
	var problemBody struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(body, &problemBody); err != nil || problemBody.Code != "audit_export_too_large" || problemBody.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("unstable size problem: %s error=%v", body, err)
	}
	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?limit=1", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("small JWS = %d %s", code, body)
	}
	var envelope auditanchor.EvidenceEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	bundle, err := audit.VerifyBundle(envelope.Bundle, key.JWKS())
	if err != nil || bundle.Count != 1 {
		t.Fatalf("small signed export: count=%d error=%v", bundle.Count, err)
	}
	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?limit=10000&format=ndjson", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("full NDJSON = %d %s", code, body)
	}
	lines := bytes.Split(bytes.TrimSpace(body), []byte("\n"))
	if len(lines) != 18 || !bytes.Contains(lines[17], []byte(`"chain_trailer"`)) {
		t.Fatalf("full stream omitted records or trailer: %d lines", len(lines))
	}
}

func TestAuditJWSExportPayloadBudgetFitsRealSignerTransport(t *testing.T) {
	cfg := config.Default()
	configureExternalAuditTestSigner(t, cfg)
	runtime, key, err := openAuditSigningRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	// Exactly 512 KiB of public JSON payload; the JWS also carries base64,
	// protected headers, signature and the signer's public identity response.
	payload := []byte(`{"note":"` + strings.Repeat("x", (512<<10)-11) + `"}`)
	if len(payload) != 512<<10 {
		t.Fatal("incorrect boundary fixture")
	}
	signed, err := key.SignArtifact(jose.ArtifactAuditExport, payload)
	if err != nil {
		t.Fatalf("bounded signer response: %v", err)
	}
	got, err := key.JWKS().VerifyArtifact(signed, jose.ArtifactAuditExport)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("boundary payload verification: %v", err)
	}
}

// This exercises the terminal evidence mirror itself, not a fleet execution.
// The pre-existing incident caller must keep every run-scoped record when its
// complete signed artifact fits the unchanged RPC but exceeds the download cap.
func TestTerminalIncidentEvidenceRetainsSignableBudgetAboveDownloadLimit(t *testing.T) {
	ctx := t.Context()
	const tenantID = "11111111-1111-4111-8111-111111111133"
	const runID = "32320000-0000-4000-8000-000000000001"
	cfg := config.Default()
	configureExternalAuditTestSigner(t, cfg)
	runtime, key, err := openAuditSigningRuntime(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "incident evidence budget"}); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	if _, err := srv.orch.RecordIncidentFleetReissuance(ctx, tenantID, store.IncidentFleetReissuanceRun{
		ID: runID, IssuerID: "32320000-0000-4000-8000-000000000002", MigrationRunID: runID,
		Mode: "game_day", PlanDigest: "bounded-evidence-fixture", Status: "planned", Phase: "plan_persisted_before_estate_work", IdempotencyKey: "incident-size-plan",
	}); err != nil {
		t.Fatal(err)
	}
	var last uint64
	for n := 0; n < 10; n++ {
		data, err := json.Marshal(map[string]any{"run_id": runID, "ordinal": n, "note": strings.Repeat("x", 53<<10)})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := log.Append(ctx, events.Event{TenantID: tenantID, Type: "audit.export.incident-size-control", Data: data})
		if err != nil {
			t.Fatal(err)
		}
		last = ev.Sequence
	}
	row := store.MigrationRun{Run: migration.Run{ID: runID, Status: migration.RunRolledBack, Incident: &migration.IncidentPlan{Mode: migration.IncidentModeGameDay}}, LastEventSequence: last}
	if err := syncIncidentMigrationState(ctx, st, srv.orch, srv.audit, tenantID, row); err != nil {
		t.Fatalf("terminal incident evidence must remain signable: %v", err)
	}
	incident, err := st.GetIncidentFleetReissuanceRun(ctx, tenantID, runID)
	if err != nil {
		t.Fatal(err)
	}
	if incident.Status != "rolled_back" || incident.EvidenceBundleFormat != "jws" {
		t.Fatalf("terminal mirror missing signed evidence: status=%s format=%s", incident.Status, incident.EvidenceBundleFormat)
	}
	bundle, err := audit.VerifyBundle(incident.EvidenceBundle, key.JWKS())
	if err != nil || bundle.Count != 11 {
		t.Fatalf("full incident evidence: count=%d err=%v", bundle.Count, err)
	}
	payload, err := json.Marshal(bundle)
	if err != nil || len(payload) <= 512<<10 || len(payload) >= 700<<10 {
		t.Fatalf("incident fixture no longer tests the accepted size region: bytes=%d err=%v", len(payload), err)
	}
	saved := incident.EvidenceBundle
	if err := syncIncidentMigrationState(ctx, st, srv.orch, srv.audit, tenantID, row); err != nil {
		t.Fatalf("terminal mirror replay: %v", err)
	}
	replayed, err := st.GetIncidentFleetReissuanceRun(ctx, tenantID, runID)
	if err != nil || replayed.EvidenceBundle != saved {
		t.Fatalf("terminal replay changed existing JWS: %v", err)
	}
}
