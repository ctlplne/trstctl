// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// TestServedIncidentMigrationRestartNeverRunsLegacyFleetBatch pins the rule
// that an incident run backed by an H2 migration run is driven only by H2. A
// control-plane restart replays the retained incident snapshot through the boot
// outbox reconciler. The legacy D6 batch lane must neither be queued for that
// run nor act on it if a command arrives: before any successor exists, D6
// summarizes an empty replacement set as fully verified and would revoke the
// wave's current identities while their hosts still serve them.
func TestServedIncidentMigrationRestartNeverRunsLegacyFleetBatch(t *testing.T) {
	ctx := context.Background()
	auditKey, err := jose.GenerateRSASigningKey("incident-restart-evidence")
	if err != nil {
		t.Fatalf("generate incident evidence key: %v", err)
	}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) {
			d.AuditSigningKey = auditKey
		})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "incident-restart-test", Status: "active",
	}); err != nil {
		t.Fatalf("register active incident agent: %v", err)
	}

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "incident-restart-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "incident-restart-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "Incident restart replacement root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"restart-aud41.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, caOperator, "create_root", "", rootSpec, 1, "incident-restart-root-ceremony")
	approveCACeremony(t, h.servedHarness, caApprover, ceremony.ID, 1, "incident-restart-root-approval")
	replacementAuthority := createRootCA(t, h.servedHarness, caOperator, ceremony.ID, rootSpec, "incident-restart-root-create")

	commander := seedScopedTokenSubject(t, h.store, h.tenant, "incident-restart-commander",
		string(authz.IncidentsRead), string(authz.IncidentsWrite), string(authz.CertsIssue), string(authz.IncidentsGameDay))
	fixture := newIncidentMigrationFixtureAUD41(t, h, "restart", "41410000-0000-4000-8000-000000000101", "production", false)
	fixture.setEnvironment(t, h, "test")

	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/incidents/fleet-reissuance-runs", commander, "incident-restart-start",
		fixture.startBody(replacementAuthority.ID, migration.IncidentModeGameDay))
	if statusCode != http.StatusCreated {
		t.Fatalf("start incident migration = %d %s", statusCode, body)
	}
	var run incidentRunResponseAUD41
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatalf("decode incident run: %v (%s)", err, body)
	}
	if run.MigrationRunID == "" || run.MigrationRunID != run.ID {
		t.Fatalf("incident run is not H2-backed: id %q migration %q", run.ID, run.MigrationRunID)
	}
	if row, err := h.store.GetMigrationRun(ctx, h.tenant, run.ID); err != nil || row.Run.Status != migration.RunRunning {
		t.Fatalf("migration run before restart = %+v err=%v; want running", row.Run.Status, err)
	}

	// Simulate the control-plane restart path: the boot reconciler replays every
	// retained event after its checkpoint, including the running incident
	// snapshot mirrored from H2.
	if _, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil {
		t.Fatalf("boot outbox reconciliation: %v", err)
	}
	var legacyQueued int
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, orchestrator.DestinationFleetReissuanceBatch).Scan(&legacyQueued); err != nil {
		t.Fatal(err)
	}
	if legacyQueued != 0 {
		t.Errorf("restart reconciler queued %d legacy D6 batch command(s) for H2-backed incident run %s", legacyQueued, run.ID)
	}

	// A legacy command that is already durable (for example queued before an
	// upgrade) must not let D6 drive the H2-owned run either.
	payload, err := json.Marshal(orchestrator.FleetReissuanceBatchCommand{RunID: run.ID, BatchIndex: 1})
	if err != nil {
		t.Fatal(err)
	}
	deliverErr := h.srv.obHandler.Deliver(ctx, orchestrator.Message{
		TenantID:       h.tenant,
		Destination:    orchestrator.DestinationFleetReissuanceBatch,
		IdempotencyKey: orchestrator.FleetReissuanceBatchIdempotencyKey(run.ID, 1),
		Payload:        payload,
	})

	state, err := h.srv.orch.State(ctx, h.tenant, fixture.identityID)
	if err != nil {
		t.Fatalf("identity state after legacy delivery: %v", err)
	}
	if state == orchestrator.StateRevoked || state == orchestrator.StateRetired {
		t.Errorf("legacy D6 delivery (err=%v) moved the in-migration identity to %s before any successor existed", deliverErr, state)
	}
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), fixture.predecessor.Serial); err != nil || !found || ledger.Revoked() {
		t.Errorf("predecessor serving certificate after legacy delivery = %+v found=%v err=%v; want not revoked", ledger, found, err)
	}
	incident, err := h.store.GetIncidentFleetReissuanceRun(ctx, h.tenant, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if incident.Status != "running" || len(incident.RevokedIdentityIDs) != 0 {
		t.Errorf("incident after legacy delivery = status %q revoked %v; want running with no revocations", incident.Status, incident.RevokedIdentityIDs)
	}
	assertMigrationOutboxCountAUD40(t, h, run.ID, "revoke_predecessor", 0)
}

// TestLegacyFleetBatchRefusesRevocationWithoutCompleteReplacementPlan pins the
// D6 completeness rule: a batch revokes its compromised identities only after
// every one of them has a replacement whose signed verification passed. An
// empty or short replacement list summarizes as zero pending receipts, which
// must never read as "all replacements verified".
func TestLegacyFleetBatchRefusesRevocationWithoutCompleteReplacementPlan(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})

	const identityID = "41410000-0000-4000-8000-000000000201"
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "legacy fleet batch owner", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.EnsureIdentity(ctx, h.tenant, identityID, store.Identity{
		Kind: store.KindX509Certificate, Name: "legacy-batch.restart-aud41.test", OwnerID: owner.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.Transition(ctx, h.tenant, identityID, orchestrator.StateIssued, "issue legacy fleet member"); err != nil {
		t.Fatal(err)
	}
	run, err := h.srv.orch.RecordIncidentFleetReissuance(ctx, h.tenant, store.IncidentFleetReissuanceRun{
		IssuerID: IssuingCAID(), Status: "running", Phase: "canary_waiting_verification",
		Reason: "legacy completeness rule", BatchSize: 1, NextBatchIndex: 1,
		AffectedIdentityIDs: []string{identityID},
		Batches: []store.FleetReissuanceBatch{{
			Index: 1, Status: servedstatus.FleetBatchWaitingVerification,
			IdentityIDs: []string{identityID}, HealthGate: servedstatus.FleetGateNotEvaluated,
		}},
	})
	if err != nil {
		t.Fatalf("record legacy incident run: %v", err)
	}

	payload, err := json.Marshal(orchestrator.FleetReissuanceBatchCommand{RunID: run.ID, BatchIndex: 1})
	if err != nil {
		t.Fatal(err)
	}
	deliverErr := h.srv.obHandler.Deliver(ctx, orchestrator.Message{
		TenantID:       h.tenant,
		Destination:    orchestrator.DestinationFleetReissuanceBatch,
		IdempotencyKey: orchestrator.FleetReissuanceBatchIdempotencyKey(run.ID, 1),
		Payload:        payload,
	})
	if deliverErr == nil {
		t.Error("legacy batch with no replacement plan was accepted")
	}
	state, err := h.srv.orch.State(ctx, h.tenant, identityID)
	if err != nil {
		t.Fatal(err)
	}
	if state == orchestrator.StateRevoked || state == orchestrator.StateRetired {
		t.Errorf("legacy batch without replacements moved its identity to %s", state)
	}
	incident, err := h.store.GetIncidentFleetReissuanceRun(ctx, h.tenant, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if incident.Status != "running" || len(incident.RevokedIdentityIDs) != 0 {
		t.Errorf("incident after refused batch = status %q revoked %v; want running with no revocations", incident.Status, incident.RevokedIdentityIDs)
	}
}
