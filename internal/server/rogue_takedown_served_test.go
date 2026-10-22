// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A43: a rogue finding names the appliance target trstctl delivered the leaf
// to with its remediation model; the takedown route queues a connector
// takedown a network relay claims, and the relay's signed report lands on the
// receipt as taken_down (or bound).
func TestServedRogueTakedownQueuesApplianceObjectRemoval(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "connector.deploy", relay.KindConnectorTakedown)
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "certs:read")
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", token, map[string]any{
		"name": "a43-bigip", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://bigip.example.test", "client_ssl_profile": "clientssl-a43", "username": "trstctl", "password_ref": "secret://connectors/a43"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create f5 target = %d %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &target)

	// An ownerless leaf trstctl delivered to that target: a non-compliant
	// finding (owner_missing) that is installed on the appliance.
	fingerprint := seedRogueDeliveredLeaf(t, ctx, h, "a43-rogue.example.test", "f5", "a43-bigip")

	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/rogue-certificates", token, nil)
	if status != http.StatusOK {
		t.Fatalf("rogue listing = %d %s", status, body)
	}
	var posture struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
			InstalledOn []struct {
				TargetID string `json:"target_id"`
				Model    string `json:"model"`
			} `json:"installed_on"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &posture); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range posture.Findings {
		if !strings.EqualFold(finding.Fingerprint, fingerprint) {
			continue
		}
		found = len(finding.InstalledOn) == 1 && finding.InstalledOn[0].TargetID == target.ID && finding.InstalledOn[0].Model == "appliance_takedown"
	}
	if !found {
		t.Fatalf("rogue listing does not name the delivered appliance target with appliance_takedown: %s", body)
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/revocation/rogue-certificates/takedown", token, "a43-takedown-1",
		map[string]any{"fingerprint": fingerprint, "target_id": target.ID, "reason": "rogue leaf confirmed"})
	if status != http.StatusAccepted {
		t.Fatalf("takedown = %d %s", status, body)
	}
	var receipt struct {
		ID          string `json:"id"`
		OutboxID    int64  `json:"outbox_id"`
		Destination string `json:"destination"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.Destination != orchestrator.DestinationConnectorTakedown ||
		receipt.Status != "takedown_queued" || receipt.OutboxID == 0 {
		t.Fatalf("queued receipt = %s err=%v", body, err)
	}

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindConnectorTakedown}, Limit: 5, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != receipt.OutboxID {
		t.Fatalf("relay claim = %+v err=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	var intent relay.TakedownIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.Connector != "f5" || intent.Target != "a43-bigip" ||
		!strings.EqualFold(intent.Fingerprint, fingerprint) || len(intent.TargetConfig) == 0 {
		t.Fatalf("intent = %+v err=%v", intent, err)
	}
	if strings.Contains(string(job.Payload), "credential.") {
		t.Fatal("takedown payload must not carry material")
	}
	report := relay.TakedownReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision, IdentityID: intent.IdentityID,
		Connector: intent.Connector, Target: intent.Target, Fingerprint: intent.Fingerprint, State: relay.TakedownRemoved}
	encoded, _ := json.Marshal(report)
	res, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(encoded), report.Digest()))
	if err != nil || !res.Accepted {
		t.Fatalf("report = %+v err=%v", res, err)
	}
	final, err := h.store.GetConnectorDeliveryReceiptForOutbox(ctx, h.tenant, receipt.OutboxID)
	if err != nil || final.Status != "taken_down" {
		t.Fatalf("final receipt = %+v err=%v", final, err)
	}

	// A leaf never delivered to the target is refused.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/revocation/rogue-certificates/takedown", token, "a43-takedown-2",
		map[string]any{"fingerprint": strings.Repeat("ab", 32), "target_id": target.ID, "reason": "x"})
	if status != http.StatusConflict {
		t.Fatalf("takedown of an undelivered leaf = %d %s, want 409", status, body)
	}
}

// A host target dispatches to the enrolled agent's material purge.
func TestServedRogueTakedownDispatchesHostTargetsToPurge(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy", relay.KindEndpointPurge)
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "certs:read")
	agentID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	f := seedPurgeFixture(t, ctx, h, token, agentID)
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/revocation/rogue-certificates/takedown", token, "a43-host-1",
		map[string]any{"fingerprint": f.fingerprint, "target_id": f.targetID, "reason": "compromised"})
	if status != http.StatusAccepted || !strings.Contains(string(body), `"destination":"endpoint.purge"`) ||
		!strings.Contains(string(body), `"status":"purge_queued"`) {
		t.Fatalf("host takedown = %d %s, want a queued purge receipt", status, body)
	}
}

// seedRogueDeliveredLeaf records an ownerless leaf and a delivered
// connector.deploy receipt naming the appliance target.
func seedRogueDeliveredLeaf(t *testing.T, ctx context.Context, h *roleHarness, name, connectorName, targetName string) string {
	t.Helper()
	key, err := crypto.GenerateHostSubjectKey(name, []string{name})
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
		Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, Source: "issued",
		CertificateDER: issued.DER, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter, ValidityAnchor: &issued.ValidityAnchor,
	})
	if err != nil {
		t.Fatalf("record certificate: %v", err)
	}
	fingerprint := strings.ToLower(cert.Fingerprint)
	outboxID := int64(900001)
	if _, err := h.srv.orch.RecordConnectorDeliveryWithEventID(ctx, h.tenant, "a43-delivered:"+targetName, store.ConnectorDeliveryReceipt{
		ID: "a4300000-0000-4000-8000-00000000d001", OutboxID: &outboxID,
		Destination: "connector.deploy", Connector: connectorName, Target: targetName, Fingerprint: fingerprint,
		Status: "delivered", Attempts: 1, Reason: "seeded", IdempotencyKey: "a43:deploy",
	}); err != nil {
		t.Fatalf("record delivered receipt: %v", err)
	}
	return fingerprint
}

// A45 + A43: a pre-trstctl pair the host agent adopted at its first deploy and
// an operator later rolled the target back to is installed on that host. The
// rogue listing names the target with host_purge for the restored predecessor,
// takedown dispatches the purge for exactly that fingerprint, and the leaf the
// rollback retired is refused with the host's current fingerprint named.
func TestServedRogueTakedownReachesAPairRestoredByRollback(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy", relay.KindEndpointPurge)
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "certs:read")
	agentID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	f := seedPurgeFixture(t, ctx, h, token, agentID)

	// The ownerless pair the agent found installed before trstctl's first
	// deploy, retained as the rollback predecessor (A45).
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
	adopted, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, Source: "host-adopted:nginx",
		CertificateDER: issued.DER, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter, ValidityAnchor: &issued.ValidityAnchor,
	})
	if err != nil {
		t.Fatalf("record adopted predecessor: %v", err)
	}
	predecessor := strings.ToLower(adopted.Fingerprint)
	// The operator rolled the target back to it: the host's signed rollback
	// result names the restored predecessor as what is installed now.
	rollbackOutbox := int64(900045)
	identityID := f.identityID
	if _, err := h.srv.orch.RecordConnectorDeliveryWithEventID(ctx, h.tenant, "a45-rolled-back:"+f.targetID, store.ConnectorDeliveryReceipt{
		ID: "a4500000-0000-4000-8000-00000000d002", OutboxID: &rollbackOutbox, IdentityID: &identityID,
		Destination: "connector.rollback", Connector: "nginx", Target: "a49-nginx", Fingerprint: predecessor,
		Status: "rolled_back", Attempts: 1, Reason: "rolled_back", IdempotencyKey: "a45:rollback",
	}); err != nil {
		t.Fatalf("record rollback receipt: %v", err)
	}

	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/rogue-certificates", token, nil)
	if status != http.StatusOK {
		t.Fatalf("rogue listing = %d %s", status, body)
	}
	var posture struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
			InstalledOn []struct {
				TargetID string `json:"target_id"`
				Model    string `json:"model"`
			} `json:"installed_on"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &posture); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range posture.Findings {
		if !strings.EqualFold(finding.Fingerprint, predecessor) {
			continue
		}
		found = len(finding.InstalledOn) == 1 && finding.InstalledOn[0].TargetID == f.targetID && finding.InstalledOn[0].Model == "host_purge"
	}
	if !found {
		t.Fatalf("rogue listing does not name the host target the rollback restored the adopted pair on: %s", body)
	}

	// Takedown of the restored pair queues the host purge for that fingerprint.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/revocation/rogue-certificates/takedown", token, "a45-takedown-1",
		map[string]any{"fingerprint": predecessor, "target_id": f.targetID, "reason": "the adopted pair must go"})
	if status != http.StatusAccepted || !strings.Contains(string(body), `"destination":"endpoint.purge"`) ||
		!strings.Contains(string(body), `"status":"purge_queued"`) || !strings.Contains(string(body), `"fingerprint":"`+predecessor+`"`) {
		t.Fatalf("takedown of the restored pair = %d %s, want a queued purge for it", status, body)
	}
	// The leaf the rollback retired is no longer what the host serves: refused,
	// naming the mismatch, and nothing queued.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/revocation/rogue-certificates/takedown", token, "a45-takedown-2",
		map[string]any{"fingerprint": f.fingerprint, "target_id": f.targetID, "reason": "stale"})
	if status != http.StatusConflict || !strings.Contains(string(body), "last delivered leaf is not this fingerprint") {
		t.Fatalf("takedown of the retired leaf = %d %s, want the host-mismatch refusal", status, body)
	}
}
