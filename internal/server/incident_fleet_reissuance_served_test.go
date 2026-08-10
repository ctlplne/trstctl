// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// AUD-31 / D6 acceptance: the request publishes only a canary command. Pause is
// a real worker gate, unsigned verification cannot release the next batch, a
// signed failure durably halts it, resume continues at the same cursor, and a
// restarted receiver cannot duplicate replacement identities or later commands.
func TestServedFleetReissuanceIsDurableCanaryFirstAcrossPauseHaltResumeAndRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and NATS; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "payments"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "fleet-incident-commander", []string{
		string(authz.IdentitiesRead), string(authz.IdentitiesWrite),
		string(authz.IssuersRead), string(authz.IssuersWrite),
		string(authz.IncidentsRead), string(authz.IncidentsWrite),
		string(authz.CertsIssue), string(authz.GraphRead),
		string(authz.ConnectorsRead), string(authz.AuditRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("aud-31-audit")
	if err != nil {
		_ = log.Close()
		t.Fatalf("generate audit key: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, AuditSigningKey: auditKey, EnableRemediation: true,
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	issuerID := createX509IssuerWithToken(t, ts, adminToken)
	firstID := createIdentityWithIssuerWithToken(t, ts, adminToken, owner.ID, issuerID, "payments-api", "fleet-identity-1")
	secondID := createIdentityWithIssuerWithToken(t, ts, adminToken, owner.ID, issuerID, "payments-worker", "fleet-identity-2")
	for _, id := range []string{firstID, secondID} {
		if code, body := transitionIdentityWithToken(t, ts, adminToken, id, "issued", "fleet-issued-"+id); code != http.StatusOK {
			t.Fatalf("issue identity %s = %d body=%s", id, code, body)
		}
		if code, body := transitionIdentityWithToken(t, ts, adminToken, id, "deployed", "fleet-deployed-"+id); code != http.StatusOK {
			t.Fatalf("deploy identity %s = %d body=%s", id, code, body)
		}
	}

	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/fleet-reissuance-runs", adminToken, "fleet-run-1", map[string]any{
		"issuer_id": issuerID, "reason": "intermediate CA private key exposure",
		"batch_size": 1, "connector": "nginx", "target": "edge/prod",
		"rollback_ref": "restore previous fullchain on every edge target",
	})
	if code != http.StatusCreated {
		t.Fatalf("start fleet reissuance = %d body=%s", code, body)
	}
	var started fleetRunTestResponse
	if err := json.Unmarshal(body, &started); err != nil {
		t.Fatalf("decode start response: %v body=%s", err, body)
	}
	if started.Status != "running" || started.Phase != "canary_queued" || started.NextBatchIndex != 1 {
		t.Fatalf("start state = %s/%s cursor=%d", started.Status, started.Phase, started.NextBatchIndex)
	}
	if len(started.ReplacementIdentityIDs) != 0 || len(started.RevokedIdentityIDs) != 0 {
		t.Fatalf("request path mutated fleet: replacements=%v revoked=%v", started.ReplacementIdentityIDs, started.RevokedIdentityIDs)
	}
	if len(started.Batches) != 2 || started.Batches[0].Status != servedstatus.FleetBatchQueued || started.Batches[1].Status != servedstatus.FleetBatchPlanned {
		t.Fatalf("start batches = %#v; want only canary queued", started.Batches)
	}
	canaryReplacement := started.Batches[0].ReplacementIdentityIDs[0]
	secondReplacement := started.Batches[1].ReplacementIdentityIDs[0]
	assertIdentityState(t, st, tenantID, firstID, orchestrator.StateDeployed)
	assertIdentityState(t, st, tenantID, secondID, orchestrator.StateDeployed)
	assertIdentityAbsent(t, st, tenantID, canaryReplacement)
	assertIdentityAbsent(t, st, tenantID, secondReplacement)

	canaryMessage := fleetBatchMessage(t, st, tenantID, started.ID, 1)
	if got := countFleetBatchCommands(t, st, tenantID, started.ID, 1); got != 1 {
		t.Fatalf("canary outbox commands = %d, want exactly 1", got)
	}
	if got := countFleetBatchCommands(t, st, tenantID, started.ID, 2); got != 0 {
		t.Fatalf("later batch was published before canary verification: %d", got)
	}

	code, pauseBody := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/fleet-reissuance-runs/"+started.ID+"/pause", adminToken, "fleet-pause-1", map[string]string{"reason": "inspect edge"})
	if code != http.StatusOK || !bytes.Contains(pauseBody, []byte(`"status":"paused"`)) {
		t.Fatalf("pause = %d body=%s", code, pauseBody)
	}
	if err := srv.obHandler.Deliver(ctx, canaryMessage); err == nil {
		t.Fatal("paused canary command was acknowledged instead of deferred")
	}
	assertIdentityAbsent(t, st, tenantID, canaryReplacement)

	code, resumeBody := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/fleet-reissuance-runs/"+started.ID+"/resume", adminToken, "fleet-resume-1", map[string]string{"reason": "continue canary"})
	if code != http.StatusOK || !bytes.Contains(resumeBody, []byte(`"phase":"batch_resumed"`)) {
		t.Fatalf("resume = %d body=%s", code, resumeBody)
	}
	if err := srv.obHandler.Deliver(ctx, canaryMessage); err == nil {
		t.Fatal("canary publish should defer while it waits for signed verification")
	}
	assertIdentityState(t, st, tenantID, canaryReplacement, orchestrator.StateIssued)
	assertIdentityAbsent(t, st, tenantID, secondReplacement)
	assertIdentityState(t, st, tenantID, firstID, orchestrator.StateDeployed)
	assertIdentityState(t, st, tenantID, secondID, orchestrator.StateDeployed)

	// A delivery row that says verify_failed but has no accepted agent signature
	// is not evidence and must not halt or advance the state machine.
	recordFleetVerification(t, st, srv.orch, tenantID, canaryReplacement, "unsigned-canary", servedstatus.ConnectorVerifyFailed, false)
	if err := srv.obHandler.Deliver(ctx, canaryMessage); err == nil {
		t.Fatal("unsigned canary receipt released the waiting command")
	}
	run := mustFleetRun(t, st, tenantID, started.ID)
	if run.Status != "running" || run.NextBatchIndex != 1 {
		t.Fatalf("unsigned receipt changed durable run: %s cursor=%d", run.Status, run.NextBatchIndex)
	}

	recordFleetVerification(t, st, srv.orch, tenantID, canaryReplacement, "signed-canary-failure", servedstatus.ConnectorVerifyFailed, true)
	if err := srv.obHandler.Deliver(ctx, canaryMessage); err == nil {
		t.Fatal("failed canary should remain pending for operator resume")
	}
	run = mustFleetRun(t, st, tenantID, started.ID)
	if run.Status != "halted" || run.HaltedReason == "" || run.Batches[0].Status != servedstatus.FleetBatchFailed || run.Batches[1].Status != servedstatus.FleetBatchHalted {
		t.Fatalf("durable halt = status=%s reason=%q batches=%#v", run.Status, run.HaltedReason, run.Batches)
	}
	if got := countFleetBatchCommands(t, st, tenantID, started.ID, 2); got != 0 {
		t.Fatalf("failed canary published batch 2: %d", got)
	}
	assertIdentityState(t, st, tenantID, firstID, orchestrator.StateDeployed)
	assertIdentityState(t, st, tenantID, secondID, orchestrator.StateDeployed)

	// The operator fixes the endpoint and a later signed receipt proves it.
	recordFleetVerification(t, st, srv.orch, tenantID, canaryReplacement, "signed-canary-success", servedstatus.ConnectorVerified, true)
	code, _ = doBearer(t, ts, http.MethodPost, "/api/v1/incidents/fleet-reissuance-runs/"+started.ID+"/resume", adminToken, "fleet-resume-2", map[string]string{"reason": "signed canary is healthy"})
	if code != http.StatusOK {
		t.Fatalf("resume halted canary = %d", code)
	}
	if err := srv.obHandler.Deliver(ctx, canaryMessage); err == nil {
		t.Fatal("resumed canary publish should first return to waiting_verification")
	}
	if err := srv.obHandler.Deliver(ctx, canaryMessage); err != nil {
		t.Fatalf("advance healthy canary: %v", err)
	}
	run = mustFleetRun(t, st, tenantID, started.ID)
	if run.NextBatchIndex != 2 || run.Batches[0].Status != servedstatus.FleetBatchExecuted || run.Batches[1].Status != servedstatus.FleetBatchQueued {
		t.Fatalf("post-canary cursor/batches = %d %#v", run.NextBatchIndex, run.Batches)
	}
	assertIdentityState(t, st, tenantID, firstID, orchestrator.StateRevoked)
	assertIdentityState(t, st, tenantID, secondID, orchestrator.StateDeployed)
	if got := countFleetBatchCommands(t, st, tenantID, started.ID, 2); got != 1 {
		t.Fatalf("batch 2 commands = %d, want exactly 1", got)
	}

	// A new receiver after restart sees the durable cursor. Replaying the old
	// canary command is an ACK-only no-op and cannot duplicate batch 2.
	restarted := &issuanceDispatcher{store: st, orch: srv.orch}
	if err := restarted.Deliver(ctx, canaryMessage); err != nil {
		t.Fatalf("restart replay of completed canary: %v", err)
	}
	if got := countFleetBatchCommands(t, st, tenantID, started.ID, 2); got != 1 {
		t.Fatalf("restart duplicated batch 2 command: %d", got)
	}

	secondMessage := fleetBatchMessage(t, st, tenantID, started.ID, 2)
	if err := restarted.Deliver(ctx, secondMessage); err == nil {
		t.Fatal("batch 2 publish should wait for verification")
	}
	if err := restarted.Deliver(ctx, secondMessage); err == nil {
		t.Fatal("replayed batch 2 should still wait without creating another identity")
	}
	assertIdentityState(t, st, tenantID, secondReplacement, orchestrator.StateIssued)
	if got := countIdentityRows(t, st, tenantID, secondReplacement); got != 1 {
		t.Fatalf("restart duplicated deterministic replacement: %d", got)
	}

	recordFleetVerification(t, st, srv.orch, tenantID, secondReplacement, "signed-batch-2-success", servedstatus.ConnectorVerified, true)
	if err := restarted.Deliver(ctx, secondMessage); err != nil {
		t.Fatalf("complete batch 2: %v", err)
	}
	run = mustFleetRun(t, st, tenantID, started.ID)
	if run.Status != "executed" || run.NextBatchIndex != 3 || len(run.RevokedIdentityIDs) != 2 || len(run.ReplacementIdentityIDs) != 2 {
		t.Fatalf("completed run = status=%s cursor=%d replacements=%v revoked=%v", run.Status, run.NextBatchIndex, run.ReplacementIdentityIDs, run.RevokedIdentityIDs)
	}
	assertIdentityState(t, st, tenantID, secondID, orchestrator.StateRevoked)
}

type fleetRunTestResponse struct {
	ID                     string   `json:"id"`
	Status                 string   `json:"status"`
	Phase                  string   `json:"phase"`
	NextBatchIndex         int      `json:"next_batch_index"`
	ReplacementIdentityIDs []string `json:"replacement_identity_ids"`
	RevokedIdentityIDs     []string `json:"revoked_identity_ids"`
	Batches                []struct {
		Index                  int      `json:"index"`
		Status                 string   `json:"status"`
		IdentityIDs            []string `json:"identity_ids"`
		ReplacementIdentityIDs []string `json:"replacement_identity_ids"`
	} `json:"batches"`
}

func fleetBatchMessage(t *testing.T, st *store.Store, tenantID, runID string, index int) orchestrator.Message {
	t.Helper()
	var m orchestrator.Message
	err := st.WithTenant(t.Context(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT id, tenant_id::text, destination, idempotency_key, payload, attempts
			FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantID,
			orchestrator.FleetReissuanceBatchIdempotencyKey(runID, index)).
			Scan(&m.ID, &m.TenantID, &m.Destination, &m.IdempotencyKey, &m.Payload, &m.Attempts)
	})
	if err != nil {
		t.Fatalf("load fleet batch %d message: %v", index, err)
	}
	return m
}

func countFleetBatchCommands(t *testing.T, st *store.Store, tenantID, runID string, index int) int {
	t.Helper()
	var count int
	if err := st.WithTenant(t.Context(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantID, orchestrator.FleetReissuanceBatchIdempotencyKey(runID, index)).Scan(&count)
	}); err != nil {
		t.Fatalf("count fleet batch commands: %v", err)
	}
	return count
}

func recordFleetVerification(t *testing.T, st *store.Store, orch *orchestrator.Orchestrator, tenantID, identityID, key, status string, signed bool) {
	t.Helper()
	var jobID int64
	if err := st.WithTenant(t.Context(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane)
			VALUES ($1, 'connector.deploy', '{}'::bytea, $2, $2) RETURNING id`, tenantID, key).Scan(&jobID)
	}); err != nil {
		t.Fatalf("insert verification job: %v", err)
	}
	if signed {
		if err := st.RecordAgentJobReceipt(t.Context(), tenantID, store.AgentJobReceipt{
			JobID: jobID, Attempt: 1, Agent: "signed-agent", Kind: "connector.deploy",
			Outcome: status, State: store.AgentJobReceiptVerified,
			SignerFingerprint: "sha256:test-agent", Statement: "canonical", Signature: "signature",
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("record signed verification receipt: %v", err)
		}
	}
	id := identityID
	if _, err := orch.RecordConnectorDelivery(t.Context(), tenantID, store.ConnectorDeliveryReceipt{
		IdentityID: &id, Destination: "connector.deploy", Connector: "nginx", Target: "edge/prod",
		Status: status, Attempts: 1, IdempotencyKey: key + ":verified",
	}); err != nil {
		t.Fatalf("record connector verification: %v", err)
	}
}

func mustFleetRun(t *testing.T, st *store.Store, tenantID, runID string) store.IncidentFleetReissuanceRun {
	t.Helper()
	run, err := st.GetIncidentFleetReissuanceRun(t.Context(), tenantID, runID)
	if err != nil {
		t.Fatalf("get fleet run: %v", err)
	}
	return run
}

func assertIdentityState(t *testing.T, st *store.Store, tenantID, identityID string, want orchestrator.State) {
	t.Helper()
	identity, err := st.GetIdentity(t.Context(), tenantID, identityID)
	if err != nil {
		t.Fatalf("get identity %s: %v", identityID, err)
	}
	if identity.Status != string(want) {
		t.Fatalf("identity %s state = %s, want %s", identityID, identity.Status, want)
	}
}

func assertIdentityAbsent(t *testing.T, st *store.Store, tenantID, identityID string) {
	t.Helper()
	if _, err := st.GetIdentity(t.Context(), tenantID, identityID); err == nil {
		t.Fatalf("identity %s exists before its batch was published", identityID)
	}
}

func countIdentityRows(t *testing.T, st *store.Store, tenantID, identityID string) int {
	t.Helper()
	var count int
	if err := st.WithTenant(t.Context(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM identities WHERE tenant_id = $1 AND id = $2`, tenantID, identityID).Scan(&count)
	}); err != nil {
		t.Fatalf("count identity rows: %v", err)
	}
	return count
}

func createX509IssuerWithToken(t *testing.T, ts *httptest.Server, token string) string {
	t.Helper()
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/issuers", token, "fleet-issuer", map[string]any{
		"kind": "x509_ca", "name": "compromised intermediate",
		"chain": []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}, "internal": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create issuer = %d body=%s", code, body)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.ID == "" {
		t.Fatalf("decode issuer id: %v body=%s", err, body)
	}
	return got.ID
}

func createIdentityWithIssuerWithToken(t *testing.T, ts *httptest.Server, token, ownerID, issuerID, name, idem string) string {
	t.Helper()
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/identities", token, idem, map[string]any{
		"kind": "x509_certificate", "name": name, "owner_id": ownerID, "issuer_id": issuerID,
	})
	if code != http.StatusCreated {
		t.Fatalf("create identity %s = %d body=%s", name, code, body)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.ID == "" {
		t.Fatalf("decode identity id: %v body=%s", err, body)
	}
	return got.ID
}

func sameMembers(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, v := range got {
		seen[v]++
	}
	for _, v := range want {
		if seen[v] == 0 {
			return false
		}
		seen[v]--
	}
	return true
}
