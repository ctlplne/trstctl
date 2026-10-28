// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/sshcollection"
	"trstctl.com/trstctl/internal/store"
)

// Start at the operator API. A reference-only, explicitly enabled network
// source must not require a host agent or contact the target while planning.
func TestServedAgentlessSSHTrustSourceIsExplicitReferenceOnlyAndEffectFree(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "ssh.trust.collect")
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a227-test", Status: "active", Executors: &transport.ExecutorReport{Version: "a227-test", Kinds: []transport.ExecutorKind{{Kind: "ssh.trust.collect"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.UpsertDiscoverySegment(t.Context(), h.tenant, store.DiscoverySegment{Name: "a227-owned", Ranges: []string{"127.0.0.1"}, StalenessHours: 24}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	input := map[string]any{"name": "owned-agentless-ssh", "kind": "ssh_trust", "config": map[string]any{"enabled": true, "segment": "a227-owned", "relay_agent_id": agentRowID(h.tenant, h.agent), "allow_loopback": true, "hosts": []map[string]any{{"address": "127.0.0.1:2222", "username": "trstctl_observe", "host_key_fingerprint": "SHA256:" + strings.Repeat("A", 43), "credential_ref": "secret://ssh/owned-read-only"}}}} // #nosec G101 -- public host pin, restricted account and vault-reference fixtures contain no credential value (CWE-798).
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", token, "a227-explicit-source", input)
	if code != http.StatusCreated {
		t.Fatalf("explicit agentless SSH trust source=%d %s; want reference-only source creation", code, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/sources/"+source.ID+"/preflight", token, nil)
	if code != http.StatusOK {
		t.Fatalf("agentless source preflight=%d %s", code, body)
	}
	var preview struct {
		Ready     bool   `json:"ready"`
		Execution string `json:"execution"`
		Protocol  string `json:"protocol"`
		Targets   int    `json:"normalized_target_count"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if !preview.Ready || preview.Protocol != "ssh_trust" || preview.Targets != 1 {
		t.Fatalf("agentless planning lost target or relay readiness: %s", body)
	}
	var queued int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='ssh.trust.collect'`, h.tenant).Scan(&queued); err != nil || queued != 0 {
		t.Fatalf("effect-free source planning queued work: %d %v", queued, err)
	}
	// Only an explicit Run creates work. An append-gap/lost outbox is rebuilt
	// from the typed source; an altered SQL payload cannot authorize redemption.
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", token, "a227-explicit-run", map[string]any{"source_id": source.ID})
	if code != http.StatusCreated {
		t.Fatalf("queue=%d %s", code, body)
	}
	var jobID int64
	var eventID string
	var payload []byte
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT id,idempotency_key,payload FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, sshcollection.Destination).Scan(&jobID, &eventID, &payload); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(), `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, jobID); err != nil {
		t.Fatal(err)
	}
	if n, err := h.srv.orch.ReconcileOutbox(t.Context(), h.log); err != nil || n < 1 {
		t.Fatalf("typed command recovery: %d %v", n, err)
	}
	if n, err := h.srv.orch.ReconcileOutbox(t.Context(), h.log); err != nil || n != 0 {
		t.Fatalf("recovery duplicated command: %d %v", n, err)
	}
	command, err := h.srv.orch.BoundSSHCollectionCommand(t.Context(), h.tenant, eventID, payload)
	if err != nil {
		t.Fatal(err)
	}
	command.Hosts[0].CredentialRef = "secret://ssh/unrelated"
	altered, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.BoundSSHCollectionCommand(t.Context(), h.tenant, eventID, altered); err == nil {
		t.Fatal("changed credential reference escaped immutable command binding")
	}
	if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND destination=$2`, h.tenant, sshcollection.Destination, altered); err != nil {
		t.Fatal(err)
	}
	claims, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{sshcollection.Destination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claims.Jobs) != 0 {
		t.Fatalf("altered source command was handed out: %+v %v", claims, err)
	}
	var attempt int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT id,claim_attempts FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, sshcollection.Destination).Scan(&jobID, &attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.RedeemJobCredential(t.Context(), &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: attempt}); err == nil {
		t.Fatal("altered SQL-only command redeemed credentials")
	}

}

func TestServedAgentlessSSHInventoryCannotForgeCollectorProvenance(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a227-host", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	response, err := h.client.ReportInventory(t.Context(), &transport.InventoryRequest{SourceKind: "ssh", Findings: []transport.InventoryFinding{{Kind: store.SSHTrustFindingKind, Ref: "/etc/ssh/sshd_config", Metadata: map[string]string{"collection_mode": "agentless", "target_address": "other.example:22"}}}})
	if err == nil {
		t.Fatalf("ordinary host report invented remote collector provenance: %+v", response)
	}
}
