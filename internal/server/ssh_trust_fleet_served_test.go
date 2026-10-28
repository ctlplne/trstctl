// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

const fleetPublicFixture = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt fleet-public-fixture"

func fleetHeartbeat(t *testing.T, a *krlAgent, enabled bool, fp, policy string) {
	t.Helper()
	readiness := map[string]any{"enabled": enabled, "confirmed": enabled}
	if enabled {
		readiness["ca_fingerprint"] = fp
		readiness["policy_digest"] = policy
	}
	raw, err := json.Marshal(map[string]any{"status": "active", "version": "a226", "executors": map[string]any{"version": "a226", "kinds": []map[string]any{{"kind": "ssh.trust.apply"}}, "ssh_trust": readiness}})
	if err != nil {
		t.Fatal(err)
	}
	var beat transport.HeartbeatRequest
	if err := json.Unmarshal(raw, &beat); err != nil {
		t.Fatal(err)
	}
	if _, err := a.client.Heartbeat(t.Context(), &beat); err != nil {
		t.Fatal(err)
	}
}

func TestServedSSHTrustFleetRequiresExactApprovalAndSkipsOptOut(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel, func(d *Deps) { d.AgentClaimableJobKinds = []string{"ssh.trust.apply"}; d.RequiredApprovals = 2 })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentChannel(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	ready := enrollKRLAgent(t, h, ln.Addr().String(), "a226-ready", []string{mtls.AgentRoleHost})
	disabled := enrollKRLAgent(t, h, ln.Addr().String(), "a226-disabled", []string{mtls.AgentRoleHost})
	key, err := sshkeys.ParsePublicKey([]byte(fleetPublicFixture))
	if err != nil {
		t.Fatal(err)
	}
	policy := "sha256:" + strings.Repeat("a", 64)
	fleetHeartbeat(t, ready, true, key.FingerprintSHA256, policy)
	fleetHeartbeat(t, disabled, false, "", "")
	token := seedScopedTokenSubject(t, h.store, h.tenant, "a226-requester", "agents:read", "agents:write", "certs:issue")
	input := map[string]any{"name": "owned-hosts", "reason": "Add the locally staged tenant CA", "public_ca_key": fleetPublicFixture, "agent_ids": []string{agentRowID(h.tenant, ready.name), agentRowID(h.tenant, disabled.name)}}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/preview", token, input)
	if status != http.StatusOK {
		t.Fatalf("SSH fleet preview = %d %s; want effect-free roster", status, body)
	}
	var preview map[string]any
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview["ready_hosts"] != float64(1) || preview["skipped_hosts"] != float64(1) || preview["effect_free"] != true {
		t.Fatalf("roster hid opt-out: %s", body)
	}
	countJobs := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='ssh.trust.apply'`, h.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if countJobs() != 0 {
		t.Fatal("preview queued trust changes")
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/approvals", token, "a226-review", preview)
	if status != http.StatusCreated {
		t.Fatalf("request approval=%d %s", status, body)
	}
	var approval map[string]any
	if err := json.Unmarshal(body, &approval); err != nil {
		t.Fatal(err)
	}
	requestID, _ := approval["approval_request_id"].(string)
	digest, _ := approval["approval_intent_digest"].(string)
	if requestID == "" || digest == "" {
		t.Fatalf("approval not bound: %s", body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/rollouts", token, "a226-unapproved", approval)
	if status != http.StatusConflict || countJobs() != 0 {
		t.Fatalf("unapproved change=%d %s jobs=%d", status, body, countJobs())
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+requestID+"/approvals", token, "a226-self", map[string]any{"intent_digest": digest})
	if status != http.StatusForbidden {
		t.Fatalf("self-review=%d %s", status, body)
	}
	for i := 0; i < 2; i++ {
		reviewer := seedScopedTokenSubject(t, h.store, h.tenant, fmt.Sprintf("a226-reviewer-%d", i), "certs:issue")
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+requestID+"/approvals", reviewer, fmt.Sprintf("a226-decision-%d", i), map[string]any{"intent_digest": digest})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("review=%d %s", status, body)
		}
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/rollouts", token, "a226-approved", approval)
	if status != http.StatusAccepted || countJobs() != 1 {
		t.Fatalf("approved dispatch=%d %s jobs=%d", status, body, countJobs())
	}
	var rollout struct {
		ID, State string
		Hosts     []struct {
			AgentID    string `json:"agent_id"`
			State      string
			SkipReason string `json:"skip_reason"`
		}
	}
	if err := json.Unmarshal(body, &rollout); err != nil {
		t.Fatal(err)
	}
	if rollout.ID == "" || rollout.State != "pending" || len(rollout.Hosts) != 2 {
		t.Fatalf("queue claimed completion: %s", body)
	}
	skipped := false
	for _, host := range rollout.Hosts {
		if host.AgentID == agentRowID(h.tenant, disabled.name) && host.State == "skipped" && host.SkipReason == "disabled" {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("opt-out absent: %s", body)
	}
	// Reviewer text is served from its privacy-cataloged source only. The effect
	// index and snapshots must not duplicate this free text or raw requester.
	var indexedPlan []byte
	var indexedRequester string
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT plan,requester FROM ssh_trust_fleet_rollouts WHERE tenant_id=$1 AND id=$2`, h.tenant, rollout.ID).Scan(&indexedPlan, &indexedRequester); err != nil {
		t.Fatal(err)
	}
	var indexed sshtrustrollout.Plan
	if err := json.Unmarshal(indexedPlan, &indexed); err != nil {
		t.Fatal(err)
	}
	if indexed.Name != "" || indexed.Reason != "" || indexedRequester == "a226-requester" || strings.Contains(string(indexedPlan), "owned-hosts") {
		t.Fatal("effect projection duplicated personal reviewer metadata outside canonical source")
	}
	var served struct {
		Plan      sshtrustrollout.Plan
		Requester string
	}
	if err := json.Unmarshal(body, &served); err != nil || served.Plan.Name != "owned-hosts" || served.Plan.Reason != "Add the locally staged tenant CA" || served.Requester != "a226-requester" {
		t.Fatalf("canonical reviewer metadata not restored to served view: %s %v", body, err)
	}

	spent, err := h.store.GetOperationApproval(t.Context(), h.tenant, requestID)
	if err != nil || spent.Status != store.ApprovalStatusConsumed || spent.ConsumedEventID != rollout.ID {
		t.Fatalf("approval not atomically consumed: %+v %v", spent, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/rollouts", token, "a226-approved", approval)
	if status != http.StatusAccepted || countJobs() != 1 {
		t.Fatalf("retry duplicated jobs: %d %s", status, body)
	}
	jobs, err := disabled.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{"ssh.trust.apply"}, Limit: 1, LeaseSeconds: 90})
	if err != nil || len(jobs.Jobs) != 0 {
		t.Fatalf("opt-out host got work: %+v %v", jobs, err)
	}
	jobs, err = ready.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{"ssh.trust.apply"}, Limit: 1, LeaseSeconds: 90})
	if err != nil || len(jobs.Jobs) != 1 || jobs.Jobs[0].Kind != "ssh.trust.apply" {
		t.Fatalf("approved host not bound: %+v %v", jobs, err)
	}
	// A well-formed derived outbox payload still needs an approved source.
	phantom, err := sshtrustrollout.DecodeCommand(bytes.NewReader(jobs.Jobs[0].Payload))
	if err != nil {
		t.Fatal(err)
	}
	phantom.RolloutID = "a2260000-0000-4000-8000-000000000099"
	rawPhantom, err := json.Marshal(phantom)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &agentService{log: h.srv.log}
	if _, err := receiver.projectSSHTrustFleetClaim(t.Context(), store.AgentJob{TenantID: h.tenant, Destination: sshtrustrollout.Destination, Payload: rawPhantom, IdempotencyKey: orchestrator.SSHTrustFleetJobKey(phantom.RolloutID, phantom.AgentID)}); err == nil {
		t.Fatal("an invented outbox row bypassed the immutable approval source")
	}
	// A corrupted read row cannot invent a completed external effect. The
	// event log still has no signed host observation for this pending claim.
	if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE ssh_trust_fleet_hosts SET state='verified' WHERE tenant_id=$1 AND rollout_id=$2 AND agent_id=$3`, h.tenant, rollout.ID, agentRowID(h.tenant, ready.name)); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/ssh/trust-fleet/rollouts/"+rollout.ID, token, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("projected state invented completion without signed source: %d %s", status, body)
	}
	// This test proves dispatch and separation of duties. It deliberately leaves
	// completion pending; the OpenSSH container journey proves the external effect.
}

func TestServedSSHTrustFleetGlobalJobSwitchStillGatesApprovedDispatch(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withAgentChannel)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "a226-switch", "agents:write")
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/rollouts", token, "a226-disabled-global", map[string]any{})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("disabled global kind accepted dispatch: %d %s", code, body)
	}
}
