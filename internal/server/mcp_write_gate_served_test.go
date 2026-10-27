// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type mcpWriteResult struct {
	Tool              string `json:"tool"`
	Outcome           string `json:"outcome"`
	IdentityID        string `json:"identity_id"`
	ApprovalRequestID string `json:"approval_request_id"`
	Text              string `json:"text"`
}

// TestServedMCPWritesTakeTheLifecycleGateA184 proves an MCP certificate write is
// never executed around the lifecycle gate: an authorized write queues the
// identity's transition, a deny-all policy refuses it, and under dual control the
// issuance is proposed (an approval request, nothing executed) and runs only when
// the same call is made after a distinct approver approved it; a rotation, which
// cannot carry an approval, is refused.
func TestServedMCPWritesTakeTheLifecycleGateA184(t *testing.T) {
	agentScopes := []string{"graph:read", "identities:read", "identities:write", "certs:request", "certs:issue"}
	issueCSR := func(t *testing.T, h *servedHarness, token, key, identityID, csr string) (int, mcpWriteResult, []byte) {
		t.Helper()
		status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/mcp/tools/issue_certificate", token, key, map[string]any{
			"identity_id": identityID, "csr_pem": csr, "reason": "agent rollout",
		})
		var got mcpWriteResult
		_ = json.Unmarshal(body, &got)
		return status, got, body
	}
	issue := func(t *testing.T, h *servedHarness, token, key, identityID string) (int, mcpWriteResult, []byte) {
		t.Helper()
		return issueCSR(t, h, token, key, identityID, mcpGateCSR(t, identityID+".mcp-gate.example.test"))
	}
	rotate := func(t *testing.T, h *servedHarness, token, key, identityID string) (int, mcpWriteResult, []byte) {
		t.Helper()
		status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/mcp/tools/rotate_certificate", token, key, map[string]any{
			"identity_id": identityID, "reason": "agent rotation",
		})
		var got mcpWriteResult
		_ = json.Unmarshal(body, &got)
		return status, got, body
	}
	statusOf := func(t *testing.T, h *servedHarness, id string) string {
		t.Helper()
		identity, err := h.store.GetIdentity(t.Context(), h.tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return identity.Status
	}

	t.Run("authorized", func(t *testing.T) {
		h := newOperatingServedHarness(t, config.Protocols{}, withMCPWriteToolsEnabled())
		token := seedScopedToken(t, h.store, h.tenant, agentScopes...)
		requested := mcpGateIdentity(t, h, "authorized-issue", orchestrator.StateRequested)
		status, got, body := issue(t, h, token, "mcp-gate-issue", requested.ID)
		if status != http.StatusOK || got.Outcome != "queued" || got.IdentityID != requested.ID {
			t.Fatalf("authorized MCP issue = %d %s", status, body)
		}
		if s := statusOf(t, h, requested.ID); s != string(orchestrator.StateIssued) {
			t.Fatalf("identity after the MCP issue = %s, want issued", s)
		}
		deployed := mcpGateIdentity(t, h, "authorized-rotate", orchestrator.StateDeployed)
		status, got, body = rotate(t, h, token, "mcp-gate-rotate", deployed.ID)
		if status != http.StatusOK || got.Outcome != "queued" {
			t.Fatalf("authorized MCP rotate = %d %s", status, body)
		}
		if s := statusOf(t, h, deployed.ID); s != string(orchestrator.StateRenewing) {
			t.Fatalf("identity after the MCP rotate = %s, want renewing", s)
		}
		if !h.hasEvent(t, "mcp.tool.write") {
			t.Fatal("the MCP writes were not audited")
		}
	})

	t.Run("deny-all policy", func(t *testing.T) {
		h := newOperatingServedHarness(t, config.Protocols{}, withMCPWriteToolsEnabled(), func(d *Deps) {
			d.EnablePolicyGate = true
			d.PolicyModule = "package trstctl.policy\ndefault allow := false\n"
		})
		token := seedScopedToken(t, h.store, h.tenant, agentScopes...)
		requested := mcpGateIdentity(t, h, "denied-issue", orchestrator.StateRequested)
		if status, _, body := issue(t, h, token, "mcp-gate-denied-issue", requested.ID); status != http.StatusForbidden || !strings.Contains(string(body), "policy") {
			t.Fatalf("MCP issue under a deny-all policy = %d %s, want 403", status, body)
		}
		deployed := mcpGateIdentity(t, h, "denied-rotate", orchestrator.StateDeployed)
		if status, _, body := rotate(t, h, token, "mcp-gate-denied-rotate", deployed.ID); status != http.StatusForbidden || !strings.Contains(string(body), "policy") {
			t.Fatalf("MCP rotate under a deny-all policy = %d %s, want 403", status, body)
		}
		if a, b := statusOf(t, h, requested.ID), statusOf(t, h, deployed.ID); a != string(orchestrator.StateRequested) || b != string(orchestrator.StateDeployed) {
			t.Fatalf("refused MCP writes changed the identities: %s, %s", a, b)
		}
	})

	t.Run("dual control", func(t *testing.T) {
		h := newOperatingServedHarness(t, config.Protocols{}, withMCPWriteToolsEnabled(), func(d *Deps) {
			d.RequireApproval = true
			d.RequiredApprovals = 1
		})
		agent := seedScopedTokenSubject(t, h.store, h.tenant, "mcp-agent@example.test", agentScopes...)
		reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "mcp-reviewer@example.test", "certs:issue", "identities:read")
		requested := mcpGateIdentity(t, h, "proposed-issue", orchestrator.StateRequested)
		csr := mcpGateCSR(t, "proposed-issue.mcp-gate.example.test")
		status, got, body := issueCSR(t, h, agent, "mcp-gate-proposed", requested.ID, csr)
		if status != http.StatusAccepted || got.Outcome != "proposed" || got.ApprovalRequestID == "" {
			t.Fatalf("MCP issue under dual control = %d %s, want 202 proposed", status, body)
		}
		if s := statusOf(t, h, requested.ID); s != string(orchestrator.StateRequested) {
			t.Fatalf("a proposed MCP issue executed: identity %s", s)
		}
		if !h.hasEvent(t, "mcp.tool.proposed") {
			t.Fatal("the proposal was not audited")
		}
		st, raw := secretsReq(t, h, http.MethodGet, "/api/v1/approval-requests", reviewer, nil)
		var listed struct {
			Items []struct {
				ID           string `json:"id"`
				IntentDigest string `json:"intent_digest"`
			} `json:"items"`
		}
		if st != http.StatusOK || json.Unmarshal(raw, &listed) != nil {
			t.Fatalf("approval requests: %d %s", st, raw)
		}
		digest := ""
		for _, it := range listed.Items {
			if it.ID == got.ApprovalRequestID {
				digest = it.IntentDigest
			}
		}
		if digest == "" {
			t.Fatalf("the proposal's approval request %s is not listed: %s", got.ApprovalRequestID, raw)
		}
		if st, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+got.ApprovalRequestID+"/approvals", reviewer,
			"mcp-gate-approve", map[string]any{"intent_digest": digest, "reason": "reviewed the agent's request"}); st/100 != 2 {
			t.Fatalf("approve: %d %s", st, raw)
		}
		// The agent makes the same call again: same arguments, same Idempotency-Key.
		status, got, body = issueCSR(t, h, agent, "mcp-gate-proposed", requested.ID, csr)
		if status != http.StatusOK || got.Outcome != "queued" {
			t.Fatalf("MCP issue after approval = %d %s, want queued", status, body)
		}
		if s := statusOf(t, h, requested.ID); s != string(orchestrator.StateIssued) {
			t.Fatalf("identity after the approved MCP issue = %s, want issued", s)
		}
		deployed := mcpGateIdentity(t, h, "refused-rotate", orchestrator.StateDeployed)
		if status, _, body := rotate(t, h, agent, "mcp-gate-dual-rotate", deployed.ID); status != http.StatusForbidden || !strings.Contains(string(body), "dual control") {
			t.Fatalf("MCP rotate under dual control = %d %s, want 403", status, body)
		}
		if s := statusOf(t, h, deployed.ID); s != string(orchestrator.StateDeployed) {
			t.Fatalf("a refused MCP rotate changed the identity: %s", s)
		}
	})

	t.Run("surface", func(t *testing.T) {
		h := newOperatingServedHarness(t, config.Protocols{}, withMCPWriteToolsEnabled())
		token := seedScopedToken(t, h.store, h.tenant, agentScopes...)
		status, body := aiReq(t, h, http.MethodGet, "/api/v1/mcp/tools", token, nil)
		var listed struct {
			Tools []string `json:"tools"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("MCP tools: %d %s", status, body)
		}
		for _, want := range []string{"issue_certificate", "rotate_certificate", "rest_transition_identity"} {
			if !slices.Contains(listed.Tools, want) {
				t.Fatalf("MCP tools miss %s: %v", want, listed.Tools)
			}
		}
		for _, never := range []string{"rest_issue_hierarchy_leaf", "rest_issue_broker_agent_identity", "rest_issue_ssh_certificate",
			"rest_approve_approval_request", "rest_approve_identity_action", "rest_deny_approval_request"} {
			if slices.Contains(listed.Tools, never) {
				t.Fatalf("MCP exposes %s, which is outside the lifecycle gate or an approval decision", never)
			}
		}
		if status, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/mcp/tools/rest_issue_hierarchy_leaf", token, "mcp-gate-direct",
			map[string]any{"path_params": map[string]string{"id": "any"}}); status != http.StatusNotFound {
			t.Fatalf("a direct CA issuance through MCP answered %d, want 404", status)
		}
		requested := mcpGateIdentity(t, h, "legacy-authority", orchestrator.StateRequested)
		if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/mcp/tools/issue_certificate", token, "mcp-gate-legacy",
			map[string]any{"identity_id": requested.ID, "authority_id": "ca-1"}); status != http.StatusBadRequest || !strings.Contains(string(body), "lifecycle identity") {
			t.Fatalf("issue_certificate with authority_id = %d %s, want 400", status, body)
		}
	})
}

// mcpGateIdentity creates an identity in the given lifecycle state through the
// orchestrator, independently of the gated MCP action under test.
func mcpGateIdentity(t *testing.T, h *servedHarness, name string, state orchestrator.State) store.Identity {
	t.Helper()
	owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "team", "mcp-gate-"+name, "lab@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: name + ".mcp-gate.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := map[orchestrator.State][]orchestrator.State{
		orchestrator.StateRequested: nil,
		orchestrator.StateDeployed:  {orchestrator.StateIssued, orchestrator.StateDeployed},
	}[state]
	for _, to := range path {
		if err := h.srv.orch.Transition(t.Context(), h.tenant, identity.ID, to, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	return identity
}

func mcpGateCSR(t *testing.T, name string) string {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
