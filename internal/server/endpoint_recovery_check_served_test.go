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
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/servedstatus"
)

// A210: after containment stopped a listener, the replacement preview reads
// the host's signed recovery check instead of assuming ready. A host without
// a pinned recovery action reads not ready; one with it reads ready.
func TestServedRecoveryCheckGatesTheReplacementPreview(t *testing.T) {
	ctx := context.Background()
	// Enabling containment enables the read-only recovery check with it.
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy", "endpoint.renew", relay.KindEndpointContain)
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "owners:read",
		"identities:read", "identities:write", "certs:read", "certs:issue", "lifecycle:read")
	agentID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	f := seedPurgeFixture(t, ctx, h, token, agentID)
	original, err := h.store.GetIdentity(ctx, h.tenant, f.identityID)
	if err != nil {
		t.Fatal(err)
	}
	original.Status = "deployed"
	original.Attributes = json.RawMessage(`{"deployment_target_id":"` + f.targetID + `"}`)
	if err := h.store.UpsertIdentity(ctx, original); err != nil {
		t.Fatal(err)
	}

	// Contain the listener through the served flow and the host's signed stop.
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/targets/"+f.targetID+"/contain/preview", token, nil)
	if status != http.StatusOK {
		t.Fatalf("containment preview = %d %s", status, body)
	}
	var plan map[string]any
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+f.targetID+"/contain", token, "a210-contain", map[string]any{
		"target_revision": plan["target_revision"], "identity_id": plan["identity_id"],
		"expected_fingerprint": plan["expected_fingerprint"], "required_agent_id": plan["required_agent_id"],
		"preview_fingerprint": plan["preview_fingerprint"], "reason": "key compromise",
	})
	if status != http.StatusAccepted {
		t.Fatalf("contain = %d %s", status, body)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointContain}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim containment = %+v err=%v", claimed, err)
	}
	var contain relay.ContainmentIntent
	if err := json.Unmarshal(claimed.Jobs[0].Payload, &contain); err != nil {
		t.Fatal(err)
	}
	before := transport.ProbeTranscript{Address: "127.0.0.1:8443", Vantage: transport.VantageLocal, Reached: true,
		ExpectedFingerprint: f.fingerprint, ObservedFingerprint: f.fingerprint, ObservedAtUnix: time.Now().Unix()}
	gone := transport.ProbeTranscript{Address: "127.0.0.1:8443", Vantage: transport.VantageLocal,
		ExpectedFingerprint: f.fingerprint, Error: "connection refused", ObservedAtUnix: time.Now().Unix()}
	stopped := relay.ContainmentReport{TargetID: contain.TargetID, TargetRevision: contain.TargetRevision,
		IdentityID: contain.IdentityID, ExpectedFingerprint: contain.ExpectedFingerprint, Action: "stop-a210",
		State: relay.ContainmentStopped, Before: before, After: []transport.ProbeTranscript{gone, gone}}
	reportRecoveryJob(t, h, claimed.Jobs[0], stopped, stopped.Digest())

	previewRequest := map[string]any{
		"replace_identity_id": f.identityID, "owner_id": original.OwnerID, "identity_name": original.Name,
		"target_id": f.targetID, "issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"},
		"reason": "replace the contained certificate",
	}
	type readiness struct {
		Ready              bool     `json:"ready"`
		RequestFingerprint string   `json:"request_fingerprint"`
		RecoverySteps      []string `json:"recovery_steps"`
		RecoveryReadiness  *struct {
			State                string   `json:"state"`
			Reasons              []string `json:"reasons"`
			ContainedFingerprint string   `json:"contained_fingerprint"`
			DeployActions        []string `json:"deploy_actions"`
			Check                *struct {
				Status         string `json:"status"`
				Recovery       string `json:"recovery"`
				RecoveryAction string `json:"recovery_action"`
				Listener       string `json:"listener"`
			} `json:"check"`
		} `json:"recovery_readiness"`
	}
	preview := func() readiness {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, previewRequest)
		if status != http.StatusOK {
			t.Fatalf("replacement preview = %d %s", status, body)
		}
		var out readiness
		if err := json.Unmarshal(body, &out); err != nil || out.RecoveryReadiness == nil {
			t.Fatalf("replacement preview without recovery readiness: %s err=%v", body, err)
		}
		return out
	}
	first := preview()
	if first.Ready || first.RecoveryReadiness.State != "unchecked" || first.RecoveryReadiness.ContainedFingerprint != f.fingerprint ||
		!strings.Contains(strings.Join(first.RecoverySteps, " "), "/recovery-check") {
		t.Fatalf("a stopped listener's replacement read ready before any host check: %+v", first)
	}
	create := map[string]any{}
	for k, v := range previewRequest {
		create[k] = v
	}
	create["preview_fingerprint"] = first.RequestFingerprint
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, "a210-replace-1", create)
	if status != http.StatusConflict || !strings.Contains(string(body), "recovery is unchecked") {
		t.Fatalf("an unchecked replacement was authorized: %d %s", status, body)
	}

	check := func(key string, answer func(relay.RecoveryCheckIntent, transport.ProbeTranscript) relay.RecoveryCheckReport) readiness {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+f.targetID+"/recovery-check",
			token, key, map[string]any{"identity_id": f.identityID})
		if status != http.StatusAccepted || !strings.Contains(string(body), `"status":"queued"`) {
			t.Fatalf("queue recovery check = %d %s", status, body)
		}
		claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointRecoveryCheck}, Limit: 1, LeaseSeconds: 60})
		if err != nil || len(claimed.Jobs) != 1 {
			t.Fatalf("claim recovery check = %+v err=%v", claimed, err)
		}
		var intent relay.RecoveryCheckIntent
		if err := json.Unmarshal(claimed.Jobs[0].Payload, &intent); err != nil || intent.TargetID != f.targetID ||
			intent.RequiredAgentID != agentID || len(intent.RevokedFingerprints) != 1 || intent.RevokedFingerprints[0] != f.fingerprint {
			t.Fatalf("recovery check intent = %+v err=%v", intent, err)
		}
		if queued := preview(); queued.Ready || queued.RecoveryReadiness.State != "queued" {
			t.Fatalf("a queued check read %+v", queued.RecoveryReadiness)
		}
		answered := answer(intent, gone)
		reportRecoveryJob(t, h, claimed.Jobs[0], answered, answered.Digest())
		status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/targets/"+f.targetID+"/recovery-check", token, nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"checked"`) {
			t.Fatalf("read recovery check = %d %s", status, body)
		}
		return preview()
	}
	digest := strings.Repeat("c", 64)
	withoutAction := check("a210-check-1", func(intent relay.RecoveryCheckIntent, probe transport.ProbeTranscript) relay.RecoveryCheckReport {
		return relay.RecoveryCheckReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
			Recovery: relay.RecoveryCheckNoRecoveryAction, Listener: relay.RecoveryListenerStopped, Probe: &probe}
	})
	if withoutAction.Ready || withoutAction.RecoveryReadiness.State != "not_ready" ||
		!strings.Contains(strings.Join(withoutAction.RecoveryReadiness.Reasons, " "), "pins no recovery action") {
		t.Fatalf("a host without a pinned recovery action read %+v", withoutAction.RecoveryReadiness)
	}
	unrun := check("a210-check-2", func(intent relay.RecoveryCheckIntent, probe transport.ProbeTranscript) relay.RecoveryCheckReport {
		return relay.RecoveryCheckReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
			Recovery: relay.RecoveryCheckPinned, RecoveryAction: "start-nginx", ExecutableSHA256: digest, ArgvSHA256: digest,
			Listener: relay.RecoveryListenerStopped, Probe: &probe}
	})
	if unrun.Ready || unrun.RecoveryReadiness.State != "not_ready" ||
		!strings.Contains(strings.Join(unrun.RecoveryReadiness.Reasons, " "), "not one the nginx connector runs") {
		t.Fatalf("a recovery action the deploy never runs read %+v", unrun.RecoveryReadiness)
	}
	pinned := check("a210-check-3", func(intent relay.RecoveryCheckIntent, probe transport.ProbeTranscript) relay.RecoveryCheckReport {
		return relay.RecoveryCheckReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
			Recovery: relay.RecoveryCheckPinned, RecoveryAction: "nginx", ExecutableSHA256: digest, ArgvSHA256: digest,
			Listener: relay.RecoveryListenerStopped, Probe: &probe}
	})
	if !pinned.Ready || pinned.RecoveryReadiness.State != "ready" || pinned.RecoveryReadiness.Check == nil ||
		pinned.RecoveryReadiness.Check.RecoveryAction != "nginx" || pinned.RecoveryReadiness.Check.Listener != "stopped" {
		t.Fatalf("a host with a pinned recovery action read %+v", pinned.RecoveryReadiness)
	}
	create["preview_fingerprint"] = pinned.RequestFingerprint
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", token, "a210-replace-2", create)
	if status != http.StatusCreated {
		t.Fatalf("a ready replacement was refused: %d %s", status, body)
	}

	// A report whose digest belongs to another answer is refused, and the
	// receipt the containment left is unchanged.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+f.targetID+"/recovery-check",
		token, "a210-check-4", map[string]any{"identity_id": f.identityID})
	if status != http.StatusAccepted {
		t.Fatalf("queue recovery check = %d %s", status, body)
	}
	tamperedJobs, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointRecoveryCheck}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(tamperedJobs.Jobs) != 1 {
		t.Fatalf("claim recovery check = %+v err=%v", tamperedJobs, err)
	}
	var intent relay.RecoveryCheckIntent
	_ = json.Unmarshal(tamperedJobs.Jobs[0].Payload, &intent)
	honest := relay.RecoveryCheckReport{TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
		Recovery: relay.RecoveryCheckNoRecoveryAction, Listener: relay.RecoveryListenerStopped, Probe: &gone}
	claimedReady := honest
	claimedReady.Recovery, claimedReady.RecoveryAction, claimedReady.ExecutableSHA256, claimedReady.ArgvSHA256 =
		relay.RecoveryCheckPinned, "nginx", digest, digest
	encoded, _ := json.Marshal(claimedReady)
	if res, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, tamperedJobs.Jobs[0].JobID, tamperedJobs.Jobs[0].Attempt,
		transport.JobOutcomeExecuted, string(encoded), honest.Digest())); err == nil && res != nil && res.Accepted {
		t.Fatal("a recovery report whose digest belongs to another answer was accepted")
	}
	receipts, err := h.store.EndpointContainmentReceipts(ctx, h.tenant, f.identityID, 8)
	if err != nil || len(receipts) != 1 || receipts[0].Status != servedstatus.ConnectorContainmentStopped {
		t.Fatalf("containment receipts = %+v err=%v", receipts, err)
	}
}

func reportRecoveryJob(t *testing.T, h *roleHarness, job transport.ClaimedJob, result any, digest string) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.client.ReportJobResult(context.Background(), signedJobReport(t, h.identity, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(encoded), digest))
	if err != nil || !res.Accepted {
		t.Fatalf("signed report = %+v err=%v", res, err)
	}
}
