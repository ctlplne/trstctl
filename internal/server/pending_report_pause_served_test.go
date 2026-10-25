// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// B13-R1: a host agent re-enrolled against a rebuilt control plane held a
// pending report sealed under its old registration. It no longer exits; it
// pauses job claims and its census says why. The agent list shows that
// reason, and a deploy bound to the agent is refused by name instead of
// waiting on a claim that never comes. A later census without the reason (the
// operator set the report aside) admits the same deploy.
func TestServedHostDeployIsRefusedWhileTheAgentHasPausedClaims(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.test", agentJobKindEndpointRenew)
	hostID := registeredRoleAgentID(t, h)
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read", "agents:read",
	)
	create := func(path string, request map[string]any) string {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodPost, path, tok, request)
		if status != http.StatusCreated {
			t.Fatalf("create %s: status %d body %s", path, status, body)
		}
		var out struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &out); err != nil || out.ID == "" {
			t.Fatalf("decode %s: %v %s", path, err, body)
		}
		return out.ID
	}
	target := create("/api/v1/connectors/targets", map[string]any{
		"name": "web/paused-claims", "connector": "nginx", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": hostID,
			"cert_path": "/etc/nginx/tls/site.crt", "key_path": "/etc/nginx/tls/site.key"},
	})
	owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "paused-claims-owner"})
	identity := create("/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "paused-claims.served.test", "owner_id": owner})
	if status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+identity+"/connector-target", tok, map[string]any{"target_id": target}); status != http.StatusOK {
		t.Fatalf("bind: status %d body %s", status, body)
	}
	deploy := func() (int, []byte) {
		t.Helper()
		return secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+target+"/deploy", tok, map[string]any{"identity_id": identity})
	}

	reason := "reportstate: pending report cannot be opened under this registration and sealing key: cipher: message authentication failed. " +
		"It was sealed under another registration or server trust (re-enrollment, a changed --ca-bundle or --server-name), its sealing key is missing, or it is damaged. " +
		"Restore those settings to send it, or stop the agent and run it once with --set-aside-pending-report to move it aside unsent; job claims stay paused until then"
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "host-test", Status: "active",
		Executors: &transport.ExecutorReport{Version: "host-test", PendingReportError: reason + strings.Repeat(" padding", 80),
			Kinds: []transport.ExecutorKind{{Kind: "endpoint.renew", Connectors: []string{"nginx"}}}}}); err != nil {
		t.Fatalf("heartbeat with paused claims: %v", err)
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/agents", tok, nil)
	var listed struct {
		Agents []struct {
			Name                       string `json:"name"`
			ReportedPendingReportError string `json:"reported_pending_report_error"`
		} `json:"agents"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
		t.Fatalf("agents list after the census: status %d body %s", status, body)
	}
	shown := ""
	for _, agent := range listed.Agents {
		if agent.Name == h.agent {
			shown = agent.ReportedPendingReportError
		}
	}
	if !strings.HasPrefix(shown, "reportstate: pending report cannot be opened") || len(shown) > 512 {
		t.Fatalf("agent list reason = %q (%d bytes), want the bounded paused-claims reason", shown, len(shown))
	}
	if status, body := deploy(); status != http.StatusConflict || !strings.Contains(string(body), h.agent) ||
		!strings.Contains(string(body), "paused job claims") || !strings.Contains(string(body), "--set-aside-pending-report") {
		t.Fatalf("deploy to an agent with paused claims: status %d body %s, want 409 naming the agent, the pause and the remedy", status, body)
	}

	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "host-test", Status: "active",
		Executors: &transport.ExecutorReport{Version: "host-test", Kinds: []transport.ExecutorKind{{Kind: "endpoint.renew", Connectors: []string{"nginx"}}}}}); err != nil {
		t.Fatalf("heartbeat after the set-aside: %v", err)
	}
	if status, body := deploy(); status == http.StatusConflict && strings.Contains(string(body), "paused job claims") {
		t.Fatalf("deploy after claims resumed is still refused: status %d body %s", status, body)
	}
}
