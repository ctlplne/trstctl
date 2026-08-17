// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type aud97SideEffect struct {
	Destination       string `json:"destination"`
	IdempotencyKey    string `json:"idempotency_key"`
	Payload           []byte `json:"payload"`
	RequiredAgentRole string `json:"required_agent_role,omitempty"`
}

type aud97ConflictList struct {
	Items []struct {
		ID                     string `json:"id"`
		TenantID               string `json:"tenant_id"`
		SourceEventID          string `json:"source_event_id"`
		SourceEventSequence    uint64 `json:"source_event_sequence"`
		IdempotencyKey         string `json:"idempotency_key"`
		ExistingOutboxID       int64  `json:"existing_outbox_id"`
		ExistingEffectLane     string `json:"existing_effect_lane"`
		ExistingPayloadSHA256  string `json:"existing_payload_sha256"`
		CandidateEffectLane    string `json:"candidate_effect_lane"`
		CandidatePayloadSHA256 string `json:"candidate_payload_sha256"`
		CandidateRequiredRole  string `json:"candidate_required_agent_role"`
		Status                 string `json:"status"`
	} `json:"items"`
	Guidance string `json:"guidance"`
}

// AUD-97 assembled upgrade proof. The durable fixture has the same identity
// IDs and reused semantic key as preserved events 73/267. Build runs the actual
// startup catch-up and outbox reconciler. Success therefore proves the conflict
// no longer takes every route and worker down, while the authenticated read
// proves the refused command is visible only to its tenant and without payloads.
func TestBuildQuarantinesHistoricalOutboxConflictAndServesRecoveryIncidentAUD97(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real PostgreSQL and file-backed JetStream")
	}
	ctx := context.Background()
	const (
		tenantA    = "11111111-1111-1111-1111-111111111111"
		tenantB    = "22222222-2222-2222-2222-222222222222"
		oldID      = "5481474d-7a8b-440a-a7df-fca7c8311dd0"
		newID      = "6ced6b6d-3777-44a8-a60f-40db05af7741"
		otherID    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		requestKey = "demo-seed-v1:identity-warehouse-mtls-deploy"
		outboxKey  = "transition:" + requestKey
	)

	st := newServerTestStore(t)
	for tenant, name := range map[string]string{tenantA: "warehouse", tenantB: "unrelated"} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: name}); err != nil {
			t.Fatalf("seed tenant %s: %v", tenant, err)
		}
	}
	ownerA, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerService, Name: "warehouse"})
	if err != nil {
		t.Fatalf("seed tenant-A owner: %v", err)
	}
	ownerB, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantB, Kind: store.OwnerService, Name: "unrelated"})
	if err != nil {
		t.Fatalf("seed tenant-B owner: %v", err)
	}
	for _, identity := range []store.Identity{
		{ID: oldID, TenantID: tenantA, Kind: store.KindX509Certificate, Name: "warehouse-old", OwnerID: ownerA.ID, Status: "issued"},
		{ID: newID, TenantID: tenantA, Kind: store.KindX509Certificate, Name: "warehouse-new", OwnerID: ownerA.ID, Status: "issued"},
		{ID: otherID, TenantID: tenantB, Kind: store.KindX509Certificate, Name: "unrelated", OwnerID: ownerB.ID, Status: "requested"},
	} {
		if err := st.UpsertIdentity(ctx, identity); err != nil {
			t.Fatalf("seed identity %s: %v", identity.ID, err)
		}
	}

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	oldPayload := aud97TransitionPayload(t, oldID, "issued", "deployed", requestKey)
	outbox := orchestrator.NewOutbox(st)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, enqueueErr := outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: outboxKey,
			EffectLane: "connector.deploy:identity:" + oldID, Payload: oldPayload,
		})
		return enqueueErr
	}); err != nil {
		t.Fatalf("seed retained pre-upgrade command: %v", err)
	}

	oldTime := time.Date(2026, time.July, 24, 15, 12, 56, 0, time.UTC)
	oldEvent, err := log.Append(ctx, events.Event{
		ID: "f3Uqbwe5fgZoBs33V9DHPx", Type: projections.EventIdentityDeployed,
		TenantID: tenantA, Time: oldTime, SchemaVersion: projections.LifecycleSideEffectEventSchemaVersion,
		Data: aud97ReplayableTransition(t, oldID, "issued", "deployed", requestKey, aud97SideEffect{
			Destination: "connector.deploy", IdempotencyKey: outboxKey, Payload: oldPayload,
		}),
	})
	if err != nil {
		t.Fatalf("append historical source event: %v", err)
	}
	if err := st.AdvanceOutboxReconciliationCheckpoint(ctx, oldEvent.Sequence); err != nil {
		t.Fatalf("advance preserved checkpoint: %v", err)
	}

	newPayload := aud97TransitionPayload(t, newID, "issued", "deployed", requestKey)
	conflictingEvent, err := log.Append(ctx, events.Event{
		ID: "kzjS2DNXhPcrCgxJlvk7We", Type: projections.EventIdentityDeployed,
		TenantID: tenantA, Time: time.Date(2026, time.August, 9, 13, 51, 41, 0, time.UTC),
		SchemaVersion: projections.LifecycleSideEffectEventSchemaVersion,
		Data: aud97ReplayableTransition(t, newID, "issued", "deployed", requestKey, aud97SideEffect{
			Destination: "connector.deploy", IdempotencyKey: outboxKey, Payload: newPayload,
			RequiredAgentRole: "control_plane",
		}),
	})
	if err != nil {
		t.Fatalf("append conflicting current event: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: "aud97-unrelated-tenant-event", Type: projections.EventIdentityIssued, TenantID: tenantB,
		Data: aud97TransitionPayload(t, otherID, "requested", "issued", "tenant-b-independent"),
	}); err != nil {
		t.Fatalf("append unrelated event: %v", err)
	}

	// Before AUD-97 this exact call returned the fatal startup error and no
	// Handler existed. It now returns a complete server after quarantining only
	// the tenant-A source event and healing tenant B.
	srv, err := Build(ctx, Deps{Store: st, Log: log})
	if err != nil {
		t.Fatalf("assembled startup over pre-upgrade fixture: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ready, err := ts.Client().Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("probe recovered readiness: %v", err)
	}
	_ = ready.Body.Close()
	if ready.StatusCode != http.StatusOK {
		t.Fatalf("recovered readiness = %d, want 200", ready.StatusCode)
	}

	var oldRows, unrelatedRows int
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, outboxKey).Scan(&oldRows); err != nil {
		t.Fatalf("count historical command: %v", err)
	}
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantB, "transition:tenant-b-independent").Scan(&unrelatedRows); err != nil {
		t.Fatalf("count unrelated healed command: %v", err)
	}
	if oldRows != 1 || unrelatedRows != 1 {
		t.Fatalf("post-start command counts old/unrelated = %d/%d, want 1/1", oldRows, unrelatedRows)
	}
	var retained []byte
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, outboxKey).Scan(&retained); err != nil {
		t.Fatalf("read retained command: %v", err)
	}
	if !bytes.Equal(retained, oldPayload) {
		t.Fatalf("startup rewrote historical command: got=%s want=%s", retained, oldPayload)
	}

	tokenA := seedScopedToken(t, st, tenantA, string(authz.IncidentsRead))
	tokenB := seedScopedToken(t, st, tenantB, string(authz.IncidentsRead))
	status, body := aud97RecoveryGET(t, ts, tokenA, tenantB)
	if status != http.StatusForbidden {
		t.Fatalf("tenant-A token with tenant-B header = %d, want 403 body=%s", status, body)
	}
	status, body = aud97RecoveryGET(t, ts, tokenA, tenantA)
	if status != http.StatusOK {
		t.Fatalf("tenant-A recovery surface = %d body=%s", status, body)
	}
	if strings.Contains(string(body), `"identity_id"`) || strings.Contains(string(body), string(oldPayload)) || strings.Contains(string(body), string(newPayload)) {
		t.Fatalf("recovery API leaked an executable payload: %s", body)
	}
	var got aud97ConflictList
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode recovery surface: %v body=%s", err, body)
	}
	if len(got.Items) != 1 {
		t.Fatalf("tenant-A conflicts = %d, want 1: %s", len(got.Items), body)
	}
	item := got.Items[0]
	if item.SourceEventID != conflictingEvent.ID || item.SourceEventSequence != conflictingEvent.Sequence ||
		item.IdempotencyKey != outboxKey || item.ExistingOutboxID <= 0 ||
		item.ExistingEffectLane != "connector.deploy:identity:"+oldID ||
		item.CandidateEffectLane != "connector.deploy:identity:"+newID ||
		item.CandidateRequiredRole != "control_plane" || item.Status != "quarantined" ||
		len(item.ExistingPayloadSHA256) != 64 || len(item.CandidatePayloadSHA256) != 64 ||
		item.ExistingPayloadSHA256 == item.CandidatePayloadSHA256 || !strings.Contains(got.Guidance, "new unique idempotency key") {
		t.Fatalf("served recovery evidence is incomplete: %+v guidance=%q", item, got.Guidance)
	}

	status, body = aud97RecoveryGET(t, ts, tokenB, tenantA)
	if status != http.StatusForbidden {
		t.Fatalf("tenant-B token with tenant-A header = %d, want 403 body=%s", status, body)
	}
	status, body = aud97RecoveryGET(t, ts, tokenB, tenantB)
	if status != http.StatusOK {
		t.Fatalf("tenant-B recovery surface = %d body=%s", status, body)
	}
	if err := json.Unmarshal(body, &got); err != nil || len(got.Items) != 0 {
		t.Fatalf("tenant B saw tenant-A recovery evidence: items=%+v err=%v body=%s", got.Items, err, body)
	}

	noIncidentToken := seedScopedToken(t, st, tenantA, string(authz.CertsRead))
	status, _ = aud97RecoveryGET(t, ts, noIncidentToken, tenantA)
	if status != http.StatusForbidden {
		t.Fatalf("certs-only token recovery surface = %d, want 403", status)
	}
}

func aud97TransitionPayload(t *testing.T, identityID, from, to, requestKey string) []byte {
	t.Helper()
	payload, err := json.Marshal(struct {
		IdentityID     string `json:"identity_id"`
		From           string `json:"from"`
		To             string `json:"to"`
		IdempotencyKey string `json:"idempotency_key"`
	}{identityID, from, to, requestKey})
	if err != nil {
		t.Fatalf("encode transition payload: %v", err)
	}
	return payload
}

func aud97ReplayableTransition(t *testing.T, identityID, from, to, requestKey string, sideEffect aud97SideEffect) []byte {
	t.Helper()
	payload, err := json.Marshal(struct {
		IdentityID     string          `json:"identity_id"`
		From           string          `json:"from"`
		To             string          `json:"to"`
		Reason         string          `json:"reason"`
		IdempotencyKey string          `json:"idempotency_key"`
		SideEffect     aud97SideEffect `json:"side_effect"`
	}{identityID, from, to, "pre-upgrade fixture", requestKey, sideEffect})
	if err != nil {
		t.Fatalf("encode replayable transition: %v", err)
	}
	return payload
}

func aud97RecoveryGET(t *testing.T, ts *httptest.Server, token, requestedTenant string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/incidents/outbox-reconciliation-conflicts", nil)
	if err != nil {
		t.Fatalf("create recovery request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", requestedTenant)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request recovery surface: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read recovery response: %v", err)
	}
	return resp.StatusCode, body.Bytes()
}
