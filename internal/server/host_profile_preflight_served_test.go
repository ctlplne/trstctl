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

// B7: a host agent whose exec profile could not be loaded claims no host
// work. Its census now says so, and a deploy bound to that host is refused by
// name instead of waiting on a claim that never comes; a later census that
// reports the profile loaded admits the same deploy.
func TestServedHostDeployIsRefusedWhileTheAgentReportsAnUnloadableProfile(t *testing.T) {
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
		"name": "web/host-profile", "connector": "nginx", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": hostID,
			"cert_path": "/etc/nginx/tls/site.crt", "key_path": "/etc/nginx/tls/site.key"},
	})
	owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "host-profile-owner"})
	identity := create("/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "host-profile.served.test", "owner_id": owner})
	if status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+identity+"/connector-target", tok, map[string]any{"target_id": target}); status != http.StatusOK {
		t.Fatalf("bind: status %d body %s", status, body)
	}
	deploy := func() (int, []byte) {
		t.Helper()
		return secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+target+"/deploy", tok, map[string]any{"identity_id": identity})
	}

	const reason = "relay: invalid tls_probe_openssl: tlsprobe: native executable /opt/homebrew/bin/openssl is a symbolic link to /opt/homebrew/Cellar/openssl@4/4.0.3/bin/openssl; pin that resolved path"
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "host-test", Status: "active",
		Executors: &transport.ExecutorReport{Version: "host-test", HostProfileError: reason, Kinds: []transport.ExecutorKind{{Kind: "endpoint.renew", Connectors: []string{"nginx"}}}}}); err != nil {
		t.Fatalf("heartbeat with an unloadable profile: %v", err)
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/agents", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"reported_host_profile_error":"relay: invalid tls_probe_openssl`) {
		t.Fatalf("agents list after the census: status %d body %s", status, body)
	}
	if status, body := deploy(); status != http.StatusConflict || !strings.Contains(string(body), h.agent) || !strings.Contains(string(body), "symbolic link to") {
		t.Fatalf("deploy to a host with an unloadable profile: status %d body %s, want 409 naming the agent and the reason", status, body)
	}

	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "host-test", Status: "active",
		Executors: &transport.ExecutorReport{Version: "host-test", HostTLSProbe: true, Kinds: []transport.ExecutorKind{{Kind: "endpoint.renew", Connectors: []string{"nginx"}}}}}); err != nil {
		t.Fatalf("heartbeat with the profile loaded: %v", err)
	}
	if status, body := deploy(); status == http.StatusConflict && strings.Contains(string(body), "could not be loaded") {
		t.Fatalf("deploy after the profile loaded is still refused for it: status %d body %s", status, body)
	}
}
