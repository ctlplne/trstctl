// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A49: an operator reviews and queues removal of a compromised leaf's
// installed material; the exact enrolled host agent claims the pinned job,
// and its signed report lands on the queued receipt as purged (or as a
// different-leaf refusal), with the files and ledger outcome in the detail.
func TestServedPurgeRemovesInstalledMaterialThroughTheEnrolledHost(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy", relay.KindEndpointPurge)
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read")
	agentID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	f := seedPurgeFixture(t, ctx, h, token, agentID)
	// The real flow leaves the identity deployed once the host served the leaf; the
	// fixture seeds the delivery receipt directly, so mirror that state here.
	if ident, err := h.store.GetIdentity(ctx, h.tenant, f.identityID); err == nil {
		ident.Status = "deployed"
		if err := h.store.UpsertIdentity(ctx, ident); err != nil {
			t.Fatal(err)
		}
	}

	// Preview names the exact leaf, agent and the purge capability.
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/targets/"+f.targetID+"/purge/preview", token, nil)
	if status != http.StatusOK {
		t.Fatalf("preview = %d %s", status, body)
	}
	var plan struct {
		Capability          string `json:"capability"`
		Ready               bool   `json:"ready"`
		TargetRevision      string `json:"target_revision"`
		IdentityID          string `json:"identity_id"`
		ExpectedFingerprint string `json:"expected_fingerprint"`
		RequiredAgentID     string `json:"required_agent_id"`
		PreviewFingerprint  string `json:"preview_fingerprint"`
	}
	if err := json.Unmarshal(body, &plan); err != nil || plan.Capability != "host_material_purge" || !plan.Ready ||
		plan.ExpectedFingerprint != f.fingerprint || plan.RequiredAgentID != agentID || plan.IdentityID != f.identityID {
		t.Fatalf("plan = %s err=%v", body, err)
	}

	request := map[string]any{
		"target_revision": plan.TargetRevision, "identity_id": plan.IdentityID,
		"expected_fingerprint": plan.ExpectedFingerprint, "required_agent_id": plan.RequiredAgentID,
		"preview_fingerprint": plan.PreviewFingerprint, "reason": "key compromise confirmed",
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+f.targetID+"/purge", token, "a49-purge-1", request)
	if status != http.StatusAccepted {
		t.Fatalf("purge = %d %s", status, body)
	}
	var receipt struct {
		ID          string `json:"id"`
		OutboxID    int64  `json:"outbox_id"`
		Destination string `json:"destination"`
		Status      string `json:"status"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.Destination != orchestrator.DestinationEndpointPurge ||
		receipt.Status != "purge_queued" || receipt.Fingerprint != f.fingerprint || receipt.OutboxID == 0 {
		t.Fatalf("queued receipt = %s err=%v", body, err)
	}
	// Same key, same job: no second row.
	status, again := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+f.targetID+"/purge", token, "a49-purge-1", request)
	if status != http.StatusAccepted || string(again) != string(body) {
		t.Fatalf("replay = %d %s", status, again)
	}

	// Only the exact host agent claims it; the command carries the target's
	// own configuration and no secret.
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointPurge}, Limit: 5, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != receipt.OutboxID {
		t.Fatalf("claim = %+v err=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	var intent relay.PurgeIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.TargetID != f.targetID ||
		intent.ExpectedFingerprint != f.fingerprint || intent.Connector != "nginx" || len(intent.TargetConfig) == 0 {
		t.Fatalf("intent = %+v err=%v", intent, err)
	}

	// The signed host report lands on the same receipt.
	report := relay.PurgeReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
		IdentityID: intent.IdentityID, ExpectedFingerprint: intent.ExpectedFingerprint, Connector: intent.Connector,
		State: relay.PurgeRemoved, ObservedFingerprint: intent.ExpectedFingerprint,
		RemovedFiles: []string{"/etc/nginx/a49.key", "/etc/nginx/a49.crt"}, LedgerWiped: true,
		Listener: relay.PurgeListenerStopped}
	encoded, _ := json.Marshal(report)
	res, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(encoded), report.Digest()))
	if err != nil || !res.Accepted {
		t.Fatalf("report = %+v err=%v", res, err)
	}
	final, err := h.store.GetConnectorDeliveryReceiptForOutbox(ctx, h.tenant, receipt.OutboxID)
	if err != nil || final.Status != "purged" || !strings.Contains(final.Detail, "/etc/nginx/a49.key") ||
		!strings.Contains(final.Detail, `"ledger_wiped":true`) {
		t.Fatalf("final receipt = %+v err=%v", final, err)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/deliveries/"+final.ID, token, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"purged"`) {
		t.Fatalf("served receipt = %d %s", status, body)
	}

	// B5-3: the purged target no longer serves the leaf, so it leaves installed_on
	// at once, and an identity served nowhere reads issued rather than deployed.
	if served, err := h.store.DeliveredTargetsForFingerprint(ctx, h.tenant, f.fingerprint); err != nil || len(served) != 0 {
		t.Fatalf("targets still serving the purged leaf = %+v err=%v; want none", served, err)
	}
	if ident, err := h.store.GetIdentity(ctx, h.tenant, f.identityID); err != nil || ident.Status != "issued" {
		t.Fatalf("identity after purge = %+v err=%v; want issued (the certificate exists, nothing serves it)", ident.Status, err)
	}

	// A tampered report (digest of a different outcome) is refused.
	tampered := report
	tampered.State = relay.PurgeDifferentLeaf
	tampered.RemovedFiles = []string{}
	tamperedBody, _ := json.Marshal(tampered)
	if res, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(tamperedBody), report.Digest())); err == nil && res != nil && res.Accepted {
		t.Fatal("a report whose digest belongs to another outcome must not be accepted")
	}
}

// A target whose family keeps material outside addressable files, or whose
// configuration names no layout, is refused at the preview.
func TestServedPurgeRefusesTargetsWithoutAFileLayout(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy", relay.KindEndpointPurge)
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read")
	agentID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", token, map[string]any{
		"name": "a49-keystore", "connector": "java-keystore", "enabled": true,
		"config": map[string]any{
			"executor": "agent", "profile": "default", "keystore_path": "/opt/app/keystore.p12",
			"keystore_password_ref": "secret://keystore", "alias": "app", "format": "pkcs12",
			"required_agent_id": agentID, "required_agent_role": mtls.AgentRoleHost,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create keystore target = %d %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &target)
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/targets/"+target.ID+"/purge/preview", token, nil)
	if status != http.StatusConflict || !strings.Contains(string(body), "file layout") {
		t.Fatalf("keystore purge preview = %d %s, want 409 naming the file layout", status, body)
	}
}

type purgeFixture struct {
	targetID, identityID, fingerprint string
}

// seedPurgeFixture creates a host target, an identity with an issued leaf and
// a delivered host deploy row so the purge preview has exact evidence.
func seedPurgeFixture(t *testing.T, ctx context.Context, h *roleHarness, token, agentID string) purgeFixture {
	t.Helper()
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", token, map[string]any{
		"name": "a49-nginx", "connector": "nginx", "enabled": true,
		"config": map[string]any{
			"executor": "agent", "profile": "default", "cert_path": "/etc/nginx/a49.crt", "key_path": "/etc/nginx/a49.key",
			"required_agent_id": agentID, "required_agent_role": mtls.AgentRoleHost,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target = %d %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil || target.ID == "" {
		t.Fatalf("decode target: %v %s", err, body)
	}
	identityID, fingerprint := seedHostDeployedIdentity(t, ctx, h, target.ID, agentID)
	return purgeFixture{targetID: target.ID, identityID: identityID, fingerprint: fingerprint}
}

// seedHostDeployedIdentity creates an owner and identity through the API,
// records a signed leaf for it, and writes the delivered host connector.deploy
// row plus its delivered receipt that bind the leaf to the identity and target.
func seedHostDeployedIdentity(t *testing.T, ctx context.Context, h *roleHarness, targetID, agentID string) (string, string) {
	t.Helper()
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write")
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a49-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner = %d %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &owner)
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind": "x509_certificate", "name": "a49.example.test", "owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity = %d %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &ident)
	key, err := crypto.GenerateHostSubjectKey("a49.example.test", []string{"a49.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.srv.issueLeafWithValidity(ctx, key.CSRDER, 24*time.Hour, crypto.LeafProfile{ClampTTLToIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(issued.DER)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		OwnerID: &owner.ID, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		Source: "issued", CertificateDER: issued.DER, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		ValidityAnchor: &issued.ValidityAnchor,
	})
	if err != nil {
		t.Fatalf("record certificate: %v", err)
	}
	fingerprint := strings.ToLower(cert.Fingerprint)
	payload := `{"connector":"nginx","target":"a49-nginx","target_id":"` + targetID + `","identity_id":"` + ident.ID + `","fingerprint":"` + fingerprint + `"}`
	var outboxID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role, required_agent_id,
			                     status, delivered_at, claimed_by_agent_id, claim_expires_at, claim_completed_at, claim_attempts)
			 VALUES ($1, 'connector.deploy', $2, 'a49:deploy', $3, 'host', $4::uuid, 'delivered', now(), $4::uuid, now() + interval '1 hour', now(), 1)
			 RETURNING id`,
			h.tenant, []byte(payload), store.ConnectorTargetLanePrefix+targetID, agentID).Scan(&outboxID)
	}); err != nil {
		t.Fatalf("seed delivered host deploy: %v", err)
	}
	identityID := ident.ID
	if _, err := h.srv.orch.RecordConnectorDeliveryWithEventID(ctx, h.tenant, "a49-delivered:"+targetID, store.ConnectorDeliveryReceipt{
		ID: "a4900000-0000-4000-8000-00000000d001", OutboxID: &outboxID, IdentityID: &identityID,
		Destination: "connector.deploy", Connector: "nginx", Target: "a49-nginx", Fingerprint: fingerprint,
		Status: "delivered", Attempts: 1, Reason: "seeded", IdempotencyKey: "a49:deploy",
	}); err != nil {
		t.Fatalf("record delivered receipt: %v", err)
	}
	return identityID, fingerprint
}
