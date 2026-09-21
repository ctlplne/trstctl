// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// JOURNEY-004/AUD-41 compatibility acceptance: old evidence stays readable,
// but the unsafe direct mutation cannot create a replacement, connector intent,
// or revocation before H1/H2 gates exist. Its conflict response points every
// caller to the exact served fleet route instead of silently doing partial work.
func TestServedIncidentExecutionRefusesMutationAndRetainsHistoryAUD41(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and NATS; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "incident-commander", []string{
		string(authz.IncidentsRead), string(authz.IncidentsWrite),
	})
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log,
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	historical, err := srv.orch.RecordIncidentExecution(ctx, tenantID, store.IncidentExecution{
		ID:                    "44444444-4444-4444-8444-444444444444",
		CompromisedIdentityID: "55555555-5555-4555-8555-555555555555",
		Status:                "executed", Phase: "legacy_evidence_only", Reason: "pre-AUD-41 retained incident",
		BlastRadius:      json.RawMessage(`{"node":{"id":"legacy"}}`),
		RevocationStatus: "legacy_recorded", EvidenceBundleFormat: "jws", EvidenceBundle: "legacy.header.signature",
		FailedTargets: []string{}, RollbackRefs: []string{"legacy:restore"},
		IdempotencyKey: "legacy-incident", CreatedBy: "historical-commander",
	})
	if err != nil {
		t.Fatalf("seed historical incident event: %v", err)
	}

	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/executions", adminToken, "incident-direct-refused", map[string]any{
		"identity_id": "66666666-6666-4666-8666-666666666666",
		"reason":      "private key export detected",
	})
	if code != http.StatusConflict || !bytes.Contains(body, []byte("/api/v1/incidents/fleet-reissuance-runs")) ||
		!bytes.Contains(body, []byte("trust-before-leaf")) {
		t.Fatalf("retired direct execution = %d body=%s; want H2 conflict guidance", code, body)
	}

	code, listBody := doBearer(t, ts, http.MethodGet, "/api/v1/incidents/executions", adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(listBody, []byte(historical.ID)) {
		t.Fatalf("list retained incident history = %d body=%s", code, listBody)
	}
	code, getBody := doBearer(t, ts, http.MethodGet, "/api/v1/incidents/executions/"+historical.ID, adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(getBody, []byte("legacy_evidence_only")) {
		t.Fatalf("get retained incident history = %d body=%s", code, getBody)
	}

	var incidentEvents int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == tenantID && event.Type == projections.EventIncidentExecutionRecorded {
			incidentEvents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if incidentEvents != 1 {
		t.Fatalf("incident execution events = %d, want only retained history", incidentEvents)
	}
	var externalIntents int
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination LIKE 'connector.%'`, tenantID).Scan(&externalIntents); err != nil {
		t.Fatal(err)
	}
	if externalIntents != 0 {
		t.Fatalf("retired direct execution queued %d connector effects", externalIntents)
	}
}
