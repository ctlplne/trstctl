// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pqcmigration"
	"trstctl.com/trstctl/internal/store"
)

// A104: a remote Envoy that declares vantage network takes its PQC TLS
// posture rollout from the network relay the target names in
// required_agent_id. The start refuses a target that names no relay; the
// queued job is pinned to that relay under the network role, survives restart
// reconciliation with its role, and the relay's signed readback completes the
// finding; the rollback returns to the same relay, which restores the
// predecessor it recorded.
func TestServedRemoteEnvoyPostureRunsOnTheRelayTheTargetNames(t *testing.T) {
	h := newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleNetwork},
		[]string{agentrelay.KindPQCPosture, agentrelay.KindPQCPostureRollback},
		// The PQC migration event schemas are registered by the licensed
		// catalog the full binary links (ee/privacy_event_policies.go, whose
		// census covers them); this core test binary does not link it.
		[]events.OpenOption{withSyntheticEventTypes},
		func(d *Deps) {
			runtime := pqcmigration.NewRuntime(d.Store)
			d.LicensedAPIOptionsFactory = runtime.APIOptionsFactory
			d.LicensedProjectionOptions = append(d.LicensedProjectionOptions, runtime.ProjectionOptions...)
			hooks := pqcmigration.HostAgentHooks{Store: d.Store, Log: d.Log, Progress: runtime.Progress, Key: d.KEK, TenantCrypto: d.TenantCrypto}
			d.PQCPostureJobOpen, d.PQCPostureJobResult = hooks.OpenJob, hooks.RecordResult
		})
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "relay-test", Status: "active"}); err != nil {
		t.Fatalf("register the relay: %v", err)
	}
	relayID := agentRowID(h.tenant, h.agent)
	const (
		targetID = "a1040000-0000-4000-8000-000000000001"
		listener = "192.0.2.10:11444"
	)
	asset, err := h.store.UpsertCryptoAsset(ctx, store.CryptoAsset{
		TenantID: h.tenant, Kind: "tls-endpoint", Location: listener, Protocol: "TLSv1.2", Strength: "acceptable",
	})
	if err != nil {
		t.Fatal(err)
	}
	upsertTarget := func(assign bool) {
		t.Helper()
		config := map[string]any{"vantage": "network", "endpoint": "http://192.0.2.10:19080", "secret_name": "edge",
			"verify_address": listener, "verify_server_name": "edge.example.test"}
		if assign {
			config["required_agent_id"] = relayID
		}
		raw, _ := json.Marshal(config)
		if err := h.store.UpsertDeploymentTarget(ctx, store.DeploymentTarget{
			ID: targetID, TenantID: h.tenant, Name: "edge-listener", Type: "envoy", Config: raw, Enabled: true, EnabledSet: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	desired := connector.TLSPosture{MinimumVersion: "TLSv1.3", KeyExchangeGroups: []string{"X25519MLKEM768", "X25519"}}
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:issue")
	start := func(key string) (int, []byte) {
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/migrations", tok, key, map[string]any{
			"asset_ids": []string{asset.ID}, "target_algorithm": "ML-DSA-65", "protocol": "acme",
			"tls_bindings": []map[string]any{{"asset_id": asset.ID, "target_id": targetID, "desired": desired}},
		})
	}
	type postureRow struct {
		ID                int64
		RequiredAgentRole string
		RequiredAgentID   string
		EffectLane        string
	}
	postureRows := func(destination string) []postureRow {
		t.Helper()
		var rows []postureRow
		r, err := h.store.SystemPool().Query(ctx, `SELECT id, required_agent_role, COALESCE(required_agent_id::text,''), effect_lane
			FROM outbox WHERE tenant_id=$1 AND destination=$2 ORDER BY id`, h.tenant, destination)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		for r.Next() {
			var row postureRow
			if err := r.Scan(&row.ID, &row.RequiredAgentRole, &row.RequiredAgentID, &row.EffectLane); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, row)
		}
		return rows
	}

	upsertTarget(false)
	if status, body := start("a104-start-unassigned"); status != http.StatusConflict || !strings.Contains(string(body), "required_agent_id") {
		t.Fatalf("start for a network target that names no relay = %d %s", status, body)
	}
	if rows := postureRows(agentrelay.KindPQCPosture); len(rows) != 0 {
		t.Fatalf("a refused start queued %d posture jobs", len(rows))
	}

	upsertTarget(true)
	status, body := start("a104-start")
	var started struct {
		RunID             string `json:"run_id"`
		TLSFindingsQueued int    `json:"tls_findings_queued"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &started) != nil || started.TLSFindingsQueued != 1 {
		t.Fatalf("start for the relay's remote Envoy = %d %s", status, body)
	}
	rows := postureRows(agentrelay.KindPQCPosture)
	if len(rows) != 1 || rows[0].RequiredAgentRole != mtls.AgentRoleNetwork || rows[0].RequiredAgentID != relayID ||
		rows[0].EffectLane != "pqc-posture:target:"+targetID {
		t.Fatalf("posture rows = %+v; want one network-role row pinned to the relay", rows)
	}
	// Boot reconciliation restores a lost row from the start event with the
	// same role and pin.
	if _, err := h.store.SystemPool().Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, agentrelay.KindPQCPosture); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.ReconcileOutbox(ctx, h.srv.log); err != nil {
		t.Fatalf("reconcile outbox: %v", err)
	}
	if rows := postureRows(agentrelay.KindPQCPosture); len(rows) != 1 || rows[0].RequiredAgentRole != mtls.AgentRoleNetwork || rows[0].RequiredAgentID != relayID {
		t.Fatalf("reconciled posture rows = %+v", rows)
	}

	claim := func(kind string) (transport.ClaimedJob, agentrelay.PQCPostureIntent) {
		t.Helper()
		claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{kind}, Limit: 1})
		if err != nil || claimed == nil || len(claimed.Jobs) != 1 {
			t.Fatalf("relay claim of %s: %v %v", kind, claimed, err)
		}
		var intent agentrelay.PQCPostureIntent
		if err := json.Unmarshal([]byte(claimed.Jobs[0].Payload), &intent); err != nil {
			t.Fatal(err)
		}
		if intent.Vantage != "network" || intent.RequiredAgentID != relayID || intent.VerifyAddress != listener {
			t.Fatalf("claimed %s intent = %+v; want the relay's network intent", kind, intent)
		}
		return claimed.Jobs[0], intent
	}
	served := agentrelay.PQCPostureServed{Address: listener, ServerName: "edge.example.test", TLSVersion: tlsprobe.TLSVersion13,
		CipherSuite: 0x1301, KeyExchangeGroup: "X25519MLKEM768", LeafFingerprint: strings.Repeat("ab", 32)}
	previous := connector.TLSPosture{MinimumVersion: "TLSv1.2", CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, KeyExchangeGroups: []string{"X25519", "P-256"}}
	report := func(job transport.ClaimedJob, kind string, receipt connector.TLSPostureReceipt, served agentrelay.PQCPostureServed) {
		t.Helper()
		result := agentrelay.PQCPostureReport{Operation: kind, Receipt: receipt, Served: served}
		detail, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeVerified, string(detail), result.Digest()))
		if err != nil || accepted == nil || !accepted.Accepted {
			t.Fatalf("relay %s report: %v %v", kind, accepted, err)
		}
	}
	job, intent := claim(agentrelay.KindPQCPosture)
	report(job, agentrelay.KindPQCPosture, connector.TLSPostureReceipt{RunID: intent.RunID, FindingID: intent.AssetID,
		FindingKind: intent.FindingKind, TargetID: intent.TargetID, TargetRevision: intent.TargetRevision, Connector: "envoy",
		Previous: previous, Observed: desired, Applied: true}, served)
	progress := func() pqcmigration.RunProgressResponse {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/pqc/migrations/"+started.RunID, tok, nil)
		var out pqcmigration.RunProgressResponse
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("progress = %d %s", status, body)
		}
		return out
	}
	if p := progress(); p.Applied != 1 || len(p.Findings) != 1 || p.Findings[0].HostReadback == nil ||
		p.Findings[0].HostReadback.AgentID != relayID || p.Findings[0].HostReadback.Served.Address != listener {
		t.Fatalf("progress after the relay's readback = %+v", p)
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/migrations/"+started.RunID+"/rollback", tok,
		"a104-rollback", map[string]any{"asset_ids": []string{asset.ID}, "reason": "a104 relay rollback"})
	if status != http.StatusAccepted {
		t.Fatalf("rollback = %d %s", status, body)
	}
	if rows := postureRows(agentrelay.KindPQCPostureRollback); len(rows) != 1 || rows[0].RequiredAgentRole != mtls.AgentRoleNetwork || rows[0].RequiredAgentID != relayID {
		t.Fatalf("rollback rows = %+v; want one network-role row pinned to the relay", rows)
	}
	rollbackJob, rollbackIntent := claim(agentrelay.KindPQCPostureRollback)
	restored := served
	restored.TLSVersion, restored.KeyExchangeGroup, restored.CipherSuite = 0x0303, "", 0xc02f
	report(rollbackJob, agentrelay.KindPQCPostureRollback, connector.TLSPostureReceipt{RunID: rollbackIntent.RunID, FindingID: rollbackIntent.AssetID,
		FindingKind: rollbackIntent.FindingKind, TargetID: rollbackIntent.TargetID, TargetRevision: rollbackIntent.TargetRevision, Connector: "envoy",
		Previous: desired, Observed: previous, Applied: true}, restored)
	if p := progress(); p.RolledBack != 1 {
		t.Fatalf("progress after the relay's rollback readback = %+v", p)
	}
	var queued int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination LIKE 'pqc.posture%' AND status <> 'delivered'`, h.tenant).Scan(&queued)
	}); err != nil || queued != 0 {
		t.Fatalf("posture rows left undelivered = %d (err=%v)", queued, err)
	}
}
